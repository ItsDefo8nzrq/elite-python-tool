#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <time.h> 

#define TIMEOUT_SECONDS 1

typedef struct {
    char *target_host;
    int start_port;
    int end_port;
    int is_tcp;
} ThreadData;

int common_ports[] = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80,
    110, 111, 123, 135, 137, 138, 139, 143, 161, 162,
    179, 389, 443, 445, 465, 500, 514, 515, 520, 546,
    547, 587, 631, 636, 873, 990, 993, 995, 1080, 1194,
    1433, 1434, 1521, 1701, 1723, 1812, 1813, 2000, 2049, 3000,
    3260, 3268, 3269, 3306, 3389, 5060, 5061, 5432, 5500, 5631,
    5800, 5900, 5901, 5902, 5903, 6000, 6001, 6002, 6003, 6667,
    8000, 8008, 8080, 8443, 9100, 9200, 9300, 27017, 27018, 37777
};

#define COMMON_PORTS_COUNT (sizeof(common_ports) / sizeof(common_ports[0]))

void *scan_port_worker(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    struct sockaddr_in server_addr;
    int sock_fd;
    int protocol = data->is_tcp ? SOCK_STREAM : SOCK_DGRAM;
    const char *proto_name = data->is_tcp ? "TCP" : "UDP";

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, data->target_host, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Worker: Invalid address/Address not supported for %s\n", data->target_host);
        free(data);
        return NULL;
    }

    for (int current_port = data->start_port; current_port <= data->end_port; current_port++) {
        if ((sock_fd = socket(AF_INET, protocol, 0)) < 0) {
            continue;
        }

        server_addr.sin_port = htons(current_port);

        struct timeval timeout;
        timeout.tv_sec = TIMEOUT_SECONDS;
        timeout.tv_usec = 0;

        if (data->is_tcp) {
            setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
            setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
        } else {
            setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
        }

        if (data->is_tcp) {
            if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) {
                printf("Port %d (%s) is open on %s\n", current_port, proto_name, data->target_host);
            }
        } else {
            char buffer[1] = {0};
            ssize_t sent_bytes = sendto(sock_fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
            if (sent_bytes > 0) {
                char recv_buffer[1024];
                socklen_t addr_len = sizeof(server_addr);
                ssize_t recv_bytes = recvfrom(sock_fd, recv_buffer, sizeof(recv_buffer) - 1, 0, NULL, NULL);
                if (recv_bytes >= 0) {
                     printf("Port %d (%s) is open on %s (UDP: received response)\n", current_port, proto_name, data->target_host);
                } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                     printf("Port %d (%s) is open|filtered on %s (UDP: timeout)\n", current_port, proto_name, data->target_host);
                } else if (errno == ECONNREFUSED) {
                }
            }
        }
        close(sock_fd);
    }

    free(data);
    return NULL;
}

void scan_common_ports(char *target_host, int is_tcp) {
    pthread_t threads_vla[COMMON_PORTS_COUNT];
    int live_thread_count = 0;

    printf("Scanning %zu common %s ports on %s...\n", COMMON_PORTS_COUNT, is_tcp ? "TCP" : "UDP", target_host);

    for (int i = 0; i < COMMON_PORTS_COUNT; i++) {
        ThreadData *thread_data_ptr = malloc(sizeof(ThreadData));
        if (!thread_data_ptr) {
            perror("Failed to allocate memory for thread data in common_ports scan");
            continue;
        }
        thread_data_ptr->target_host = target_host;
        thread_data_ptr->start_port = common_ports[i];
        thread_data_ptr->end_port = common_ports[i];
        thread_data_ptr->is_tcp = is_tcp;

        if (pthread_create(&threads_vla[live_thread_count], NULL, scan_port_worker, thread_data_ptr) != 0) {
            perror("Failed to create thread in common_ports scan");
            free(thread_data_ptr);
        } else {
            live_thread_count++;
        }
    }

    for (int i = 0; i < live_thread_count; i++) {
        pthread_join(threads_vla[i], NULL);
    }
    printf("Finished scanning common ports.\n");
}

void scan_port_range(char *target_host, int start_scan_port, int end_scan_port, int num_threads_requested, int is_tcp) {
    if (start_scan_port < 1 || end_scan_port > 65535 || start_scan_port > end_scan_port) {
        fprintf(stderr, "Invalid port range (%d-%d).\n", start_scan_port, end_scan_port);
        return;
    }
    if (num_threads_requested <= 0) {
        fprintf(stderr, "Number of threads must be positive. Using default 10.\n");
        num_threads_requested = 10;
    }

    int total_ports_to_scan = end_scan_port - start_scan_port + 1;
    int actual_num_threads = num_threads_requested;

    if (total_ports_to_scan < num_threads_requested) {
        actual_num_threads = total_ports_to_scan;
    }
    if (actual_num_threads == 0 && total_ports_to_scan > 0) {
        actual_num_threads = 1;
    }
    if (actual_num_threads == 0) {
        printf("No ports to scan or zero threads determined for the given range.\n");
        return;
    }

    pthread_t *threads_arr = malloc(actual_num_threads * sizeof(pthread_t));
    if (!threads_arr) {
        perror("Failed to allocate memory for thread IDs in range scan");
        return;
    }

    printf("Scanning %s ports %d-%d on %s using %d threads...\n",
           is_tcp ? "TCP" : "UDP", start_scan_port, end_scan_port, target_host, actual_num_threads);

    int ports_per_thread_base = total_ports_to_scan / actual_num_threads;
    int remaining_ports = total_ports_to_scan % actual_num_threads;
    int current_port_assignment_starts = start_scan_port;
    int live_thread_count = 0;

    for (int i = 0; i < actual_num_threads; i++) {
        int ports_for_this_thread = ports_per_thread_base + (i < remaining_ports ? 1 : 0);
        if (ports_for_this_thread == 0) {
            continue;
        }

        ThreadData *data = malloc(sizeof(ThreadData));
        if (!data) {
            perror("Failed to allocate memory for thread data in range scan");
            continue;
        }

        data->target_host = target_host;
        data->start_port = current_port_assignment_starts;
        data->end_port = current_port_assignment_starts + ports_for_this_thread - 1;
        data->is_tcp = is_tcp;

        if (pthread_create(&threads_arr[live_thread_count], NULL, scan_port_worker, data) != 0) {
            perror("Failed to create thread in range scan");
            free(data);
        } else {
            live_thread_count++;
        }
        current_port_assignment_starts += ports_for_this_thread;
    }

    for (int i = 0; i < live_thread_count; i++) {
        pthread_join(threads_arr[i], NULL);
    }

    free(threads_arr);
    printf("Finished scanning port range.\n");
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <target_host> <scan_type> [options]\n", argv[0]);
        fprintf(stderr, "Scan types:\n");
        fprintf(stderr, "  common-tcp       Scan common TCP ports\n");
        fprintf(stderr, "  common-udp       Scan common UDP ports\n");
        fprintf(stderr, "  range-tcp        <start_port> <end_port> [num_threads (default 10)]\n");
        fprintf(stderr, "  range-udp        <start_port> <end_port> [num_threads (default 10)]\n");
        return 1;
    }

    char *target_host = argv[1];
    char *scan_type = argv[2];

    if (strcmp(scan_type, "common-tcp") == 0) {
        scan_common_ports(target_host, 1);
    } else if (strcmp(scan_type, "common-udp") == 0) {
        scan_common_ports(target_host, 0);
    } else if (strcmp(scan_type, "range-tcp") == 0 || strcmp(scan_type, "range-udp") == 0) {
        if (argc < 5) {
            fprintf(stderr, "Usage: %s %s %s <start_port> <end_port> [num_threads]\n", argv[0], target_host, scan_type);
            return 1;
        }
        int start_port = atoi(argv[3]);
        int end_port = atoi(argv[4]);
        int num_threads = 10;
        if (argc > 5) {
            num_threads = atoi(argv[5]);
            if (num_threads <= 0) num_threads = 10;
        }
        int is_tcp = (strcmp(scan_type, "range-tcp") == 0);
        scan_port_range(target_host, start_port, end_port, num_threads, is_tcp);
    } else {
        fprintf(stderr, "Invalid scan type: %s\n", scan_type);
        return 1;
    }

    return 0;
}
