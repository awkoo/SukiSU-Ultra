#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <android/log.h>
#include <time.h>
#include <stdarg.h>

// Android logging macros
#define LOG_TAG "User_UID_Scanner"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// File paths and constants
#define USER_DATA_BASE_PATH "/data/user_de"
#define KSU_UID_LIST_PATH "/data/misc/user_uid/uid_list"
#define PROC_COMM_PATH "/proc/ksu_uid_scanner"
#define PID_FILE_PATH "/data/misc/user_uid/uid_scanner.pid"
#define LOG_FILE_PATH "/data/misc/user_uid/uid_scanner.log"
#define CONFIG_FILE_PATH "/data/misc/user_uid/uid_scanner.conf"

// Buffer and limit constants
#define MAX_PACKAGE_NAME 256
#define MAX_PATH_LEN 512
#define MAX_LOG_SIZE (1024 * 1024)  // 1MB
#define MAX_USERS 8

// Language support enumeration
typedef enum {
    LANG_EN = 0,
    LANG_ZH = 1
} language_t;

// Configuration structure
struct scanner_config {
    language_t language;
    int multi_user_scan;
    int scan_interval;
    int log_level;
};

// UID data structure with linked list
struct uid_data {
    int uid;
    char package[MAX_PACKAGE_NAME];
    struct uid_data *next;
};

// Multi-language message structure
typedef struct {
    const char *en;
    const char *zh;
} message_t;

// Global variables
static volatile int should_exit = 0;
static volatile int should_reload = 0;
static struct uid_data *uid_list_head = NULL;
static int log_fd = -1;

// Default configuration
static struct scanner_config config = {
    .language = LANG_EN,        // Default to English
    .multi_user_scan = 0,       // Default single user scan
    .scan_interval = 5,         // Default 5 seconds
    .log_level = 1              // Default INFO level
};

// Function prototypes
int save_config(void);

// Message dictionary for multi-language support
static const message_t messages[] = {
    {"Received termination signal %d, preparing to exit", "收到终止信号 %d，准备退出"},
    {"Received reload signal, preparing to rescan", "收到重载信号，准备重新扫描"},
    {"Received user signal, forced rescan", "收到用户信号，强制重新扫描"},
    {"Log file rotated", "日志文件已轮转"},
    {"First fork failed: %s", "第一次fork失败: %s"},
    {"setsid failed: %s", "setsid失败: %s"},
    {"Second fork failed: %s", "第二次fork失败: %s"},
    {"Cannot change working directory: %s", "切换工作目录失败: %s"},
    {"Cannot create PID file %s: %s", "无法创建PID文件 %s: %s"},
    {"PID file created: %d", "PID文件已创建: %d"},
    {"Daemon is not running", "守护进程未运行"},
    {"Stopping daemon process (PID: %d)...", "正在停止守护进程 (PID: %d)..."},
    {"Failed to send termination signal: %s", "发送终止信号失败: %s"},
    {"Daemon stopped", "守护进程已停止"},
    {"Force terminating daemon...", "正在强制终止守护进程..."},
    {"Daemon force stopped", "守护进程已强制停止"},
    {"Cannot stop daemon", "无法停止守护进程"},
    {"Restarting daemon...", "正在重启守护进程..."},
    {"Cannot stop old daemon", "无法停止旧的守护进程"},
    {"Starting new daemon...", "正在启动新的守护进程..."},
    {"Daemon status: Not running", "守护进程状态: 未运行"},
    {"Daemon status: Running (PID: %d)", "守护进程状态: 运行中 (PID: %d)"},
    {"Recent log entries:", "最近的日志条目:"},
    {"Daemon status: Stopped (stale PID file)", "守护进程状态: 已停止 (陈旧的PID文件)"},
    {"Sending reload signal to daemon (PID: %d)...", "正在发送重载信号到守护进程 (PID: %d)..."},
    {"Reload signal sent", "重载信号已发送"},
    {"Failed to send reload signal: %s", "发送重载信号失败: %s"},
    {"Cannot open directory %s: %s", "无法打开目录 %s: %s"},
    {"Starting user data directory scan", "开始扫描用户数据目录"},
    {"Package name too long: %s", "包名过长: %s"},
    {"Cannot get file status %s: %s", "无法获取文件状态 %s: %s"},
    {"Memory allocation failed", "内存分配失败"},
    {"Scan completed, found %d packages", "扫描完成，发现 %d 个包"},
    {"Cannot open whitelist file %s: %s", "无法打开白名单文件 %s: %s"},
    {"Written %d entries to UID whitelist", "已写入 %d 个条目到UID白名单"},
    {"Cannot open kernel communication file %s: %s", "无法打开内核通信文件 %s: %s"},
    {"Cannot write to kernel communication file %s: %s", "无法写入内核通信文件 %s: %s"},
    {"Kernel update notification sent", "已通知内核更新完成"},
    {"Performing UID scan and update", "执行UID扫描和更新"},
    {"UID scan failed", "UID扫描失败"},
    {"Whitelist write failed", "写入白名单失败"},
    {"Scan and update completed successfully", "扫描和更新成功完成"},
    {"Whitelist file not found or open failed: %s", "未找到白名单文件或打开失败: %s"},
    {"Current UID whitelist:", "当前UID白名单:"},
    {"Performing one-time scan...", "执行一次性扫描..."},
    {"Invalid argument: %s", "无效的参数: %s"},
    {"Daemon already running", "守护进程已在运行中"},
    {"Starting daemon process...", "正在启动守护进程..."},
    {"Daemon startup failed", "守护进程启动失败"},
    {"UID Scanner daemon started", "UID扫描器守护进程启动"},
    {"Received reload request, performing scan update", "收到重载请求，执行扫描更新"},
    {"Kernel requested rescan", "内核请求重新扫描"},
    {"Daemon is exiting", "守护进程正在退出"},
    {"UID Scanner daemon exited", "UID扫描器守护进程已退出"},
    {"Configuration loaded successfully", "配置加载成功"},
    {"Configuration saved successfully", "配置保存成功"},
    {"Failed to load configuration: %s", "加载配置失败: %s"},
    {"Failed to save configuration: %s", "保存配置失败: %s"},
    {"Language switched to English", "语言已切换到英文"},
    {"Language switched to Chinese", "语言已切换到中文"},
    {"Multi-user scanning enabled", "多用户扫描已启用"},
    {"Multi-user scanning disabled", "多用户扫描已禁用"},
    {"Scanning user directory: %s", "扫描用户目录: %s"},
    {"Found %d active users for scanning", "发现 %d 个活跃用户进行扫描"},
    {"Using fallback method to detect users", "使用备用方法检测用户"}
};

#define MSG_COUNT (sizeof(messages) / sizeof(messages[0]))

// Get localized message by index
const char* get_message(int msg_id) {
    if (msg_id < 0 || msg_id >= (int)MSG_COUNT) {
        return "Unknown message";
    }
    return (config.language == LANG_ZH) ? messages[msg_id].zh : messages[msg_id].en;
}

// Enhanced logging with timestamp and localization
void write_daemon_log(const char *level, int msg_id, ...) {
    char buffer[1024];
    char formatted_msg[1024];
    char timestamp[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    va_list args;
    
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    va_start(args, msg_id);
    vsnprintf(formatted_msg, sizeof(formatted_msg), get_message(msg_id), args);
    va_end(args);
    
    snprintf(buffer, sizeof(buffer), "[%s] %s: %s", timestamp, level, formatted_msg);
    
    if (log_fd != -1) {
        dprintf(log_fd, "%s\n", buffer);
        fsync(log_fd);
    }
    
    // Send to Android log system
    if (strcmp(level, "ERROR") == 0) {
        LOGE("%s", formatted_msg);
    } else {
        LOGI("%s", formatted_msg);
    }
}

// Ensure directory exists
void ensure_directory_exists(void) {
    system("mkdir -p /data/misc/user_uid");
}

// Parse configuration key-value pair
void parse_config_line(const char *key, const char *value) {
    if (strcmp(key, "language") == 0) {
        config.language = (strcmp(value, "zh") == 0) ? LANG_ZH : LANG_EN;
    } else if (strcmp(key, "multi_user_scan") == 0) {
        config.multi_user_scan = atoi(value);
    } else if (strcmp(key, "scan_interval") == 0) {
        config.scan_interval = atoi(value);
        if (config.scan_interval < 1) {
            config.scan_interval = 5;
        }
    } else if (strcmp(key, "log_level") == 0) {
        config.log_level = atoi(value);
    }
}

// Load configuration from file
int load_config(void) {
    FILE *fp = fopen(CONFIG_FILE_PATH, "r");
    if (!fp) {
        return save_config();  // Create default config if not exists
    }
    
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char key[64], value[64];
        if (sscanf(line, "%63[^=]=%63s", key, value) == 2) {
            parse_config_line(key, value);
        }
    }
    
    fclose(fp);
    write_daemon_log("INFO", 54);  // Configuration loaded successfully
    return 0;
}

// Save configuration to file
int save_config(void) {
    ensure_directory_exists();
    
    FILE *fp = fopen(CONFIG_FILE_PATH, "w");
    if (!fp) {
        write_daemon_log("ERROR", 57, strerror(errno));  // Failed to save configuration
        return -1;
    }
    
    fprintf(fp, "language=%s\n", (config.language == LANG_ZH) ? "zh" : "en");
    fprintf(fp, "multi_user_scan=%d\n", config.multi_user_scan);
    fprintf(fp, "scan_interval=%d\n", config.scan_interval);
    fprintf(fp, "log_level=%d\n", config.log_level);
    
    fclose(fp);
    write_daemon_log("INFO", 55);  // Configuration saved successfully
    return 0;
}

// Set language configuration
void set_language(language_t lang) {
    config.language = lang;
    save_config();
    write_daemon_log("INFO", (lang == LANG_ZH) ? 59 : 58);  // Language switched
}

// Set multi-user scan configuration
void set_multi_user_scan(int enabled) {
    config.multi_user_scan = enabled;
    save_config();
    write_daemon_log("INFO", enabled ? 60 : 61);  // Multi-user scanning enabled/disabled
}

// Signal handler for daemon control
void signal_handler(int sig) {
    switch (sig) {
        case SIGTERM:
        case SIGINT:
            should_exit = 1;
            write_daemon_log("INFO", 0, sig);  // Received termination signal
            break;
        case SIGHUP:
            should_reload = 1;
            write_daemon_log("INFO", 1);  // Received reload signal
            break;
        case SIGUSR1:
            should_reload = 1;
            write_daemon_log("INFO", 2);  // Received user signal
            break;
        default:
            break;
    }
}

// Manage log file size and rotation
void manage_log_file(void) {
    struct stat st;
    if (log_fd == -1 || fstat(log_fd, &st) != 0) {
        return;
    }
    
    if (st.st_size > MAX_LOG_SIZE) {
        close(log_fd);
        char backup_path[MAX_PATH_LEN];
        snprintf(backup_path, sizeof(backup_path), "%s.old", LOG_FILE_PATH);
        rename(LOG_FILE_PATH, backup_path);
        log_fd = open(LOG_FILE_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (log_fd != -1) {
            write_daemon_log("INFO", 3);  // Log file rotated
        }
    }
}

// Setup standard file descriptors for daemon
void setup_daemon_stdio(void) {
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    open("/dev/null", O_RDONLY);   // stdin
    open("/dev/null", O_WRONLY);   // stdout
    open("/dev/null", O_WRONLY);   // stderr
}

// Create daemon process with double fork
int daemonize(void) {
    pid_t pid;
    
    // First fork
    pid = fork();
    if (pid < 0) {
        LOGE(get_message(4), strerror(errno));  // First fork failed
        return -1;
    }
    if (pid > 0) {
        exit(0);  // Parent exits
    }
    
    // Create new session
    if (setsid() < 0) {
        LOGE(get_message(5), strerror(errno));  // setsid failed
        return -1;
    }
    
    // Second fork to prevent acquiring a controlling terminal
    signal(SIGHUP, SIG_IGN);
    pid = fork();
    if (pid < 0) {
        LOGE(get_message(6), strerror(errno));  // Second fork failed
        return -1;
    }
    if (pid > 0) {
        exit(0);  // First child exits
    }
    
    // Set file permission mask
    umask(0);
    
    // Change working directory
    if (chdir("/") < 0) {
        LOGE(get_message(7), strerror(errno));  // Cannot change working directory
        return -1;
    }
    
    setup_daemon_stdio();
    return 0;
}

// Write current process ID to PID file
int write_pid_file(void) {
    ensure_directory_exists();
    
    FILE *fp = fopen(PID_FILE_PATH, "w");
    if (!fp) {
        write_daemon_log("ERROR", 8, PID_FILE_PATH, strerror(errno));  // Cannot create PID file
        return -1;
    }
    
    fprintf(fp, "%d\n", getpid());
    fclose(fp);
    
    write_daemon_log("INFO", 9, getpid());  // PID file created
    return 0;
}

// Read PID from PID file
pid_t read_pid_file(void) {
    FILE *fp = fopen(PID_FILE_PATH, "r");
    if (!fp) {
        return 0;
    }
    
    pid_t pid = 0;
    if (fscanf(fp, "%d", &pid) != 1) {
        pid = 0;
    }
    
    fclose(fp);
    return pid;
}

// Check if daemon process is running
int is_daemon_running(void) {
    pid_t pid = read_pid_file();
    if (pid <= 0) {
        return 0;
    }
    
    if (kill(pid, 0) == 0) {
        return 1;
    } else {
        unlink(PID_FILE_PATH);  // Remove stale PID file
        return 0;
    }
}

// Stop daemon with graceful termination
int stop_daemon(void) {
    pid_t pid = read_pid_file();
    if (pid <= 0) {
        printf("%s\n", get_message(10));  // Daemon is not running
        return 0;
    }
    
    printf(get_message(11), pid);  // Stopping daemon process
    printf("\n");
    
    // Send SIGTERM signal
    if (kill(pid, SIGTERM) != 0) {
        printf(get_message(12), strerror(errno));  // Failed to send termination signal
        printf("\n");
        return -1;
    }
    
    // Wait for process to exit (up to 30 seconds)
    for (int attempts = 0; attempts < 30; attempts++) {
        if (kill(pid, 0) != 0) {
            printf("%s\n", get_message(13));  // Daemon stopped
            unlink(PID_FILE_PATH);
            return 0;
        }
        sleep(1);
    }
    
    // Force terminate if graceful shutdown failed
    printf("%s\n", get_message(14));  // Force terminating daemon
    if (kill(pid, SIGKILL) == 0) {
        printf("%s\n", get_message(15));  // Daemon force stopped
        unlink(PID_FILE_PATH);
        return 0;
    }
    
    printf("%s\n", get_message(16));  // Cannot stop daemon
    return -1;
}

// Restart daemon process
int restart_daemon(void) {
    printf("%s\n", get_message(17));  // Restarting daemon
    stop_daemon();
    sleep(2);
    
    if (is_daemon_running()) {
        printf("%s\n", get_message(18));  // Cannot stop old daemon
        return -1;
    }
    
    printf("%s\n", get_message(19));  // Starting new daemon
    return 0;
}

// Show daemon status and recent logs
void show_status(void) {
    pid_t pid = read_pid_file();
    if (pid <= 0) {
        printf("%s\n", get_message(20));  // Daemon status: Not running
        return;
    }
    
    if (kill(pid, 0) == 0) {
        printf(get_message(21), pid);  // Daemon status: Running
        printf("\n");
        
        // Show recent log entries if log file exists
        if (access(LOG_FILE_PATH, R_OK) == 0) {
            printf("\n%s\n", get_message(22));  // Recent log entries
            char cmd[512];
            snprintf(cmd, sizeof(cmd), "tail -n 10 %s", LOG_FILE_PATH);
            system(cmd);
        }
    } else {
        printf("%s\n", get_message(23));  // Daemon status: Stopped (stale PID file)
        unlink(PID_FILE_PATH);
    }
}

// Send reload signal to daemon
void reload_daemon(void) {
    pid_t pid = read_pid_file();
    if (pid <= 0 || kill(pid, 0) != 0) {
        printf("%s\n", get_message(10));  // Daemon is not running
        return;
    }
    
    printf(get_message(24), pid);  // Sending reload signal to daemon
    printf("\n");
    
    if (kill(pid, SIGUSR1) == 0) {
        printf("%s\n", get_message(25));  // Reload signal sent
    } else {
        printf(get_message(26), strerror(errno));  // Failed to send reload signal
        printf("\n");
    }
}

// Try to get user list from Android package manager
int get_users_from_pm(char user_dirs[][MAX_PATH_LEN], int max_users) {
    FILE *fp = popen("pm list users 2>/dev/null | grep 'UserInfo{' | sed 's/.*UserInfo{\\([0-9]*\\):.*/\\1/'", "r");
    if (!fp) {
        return 0;
    }
    
    int user_count = 0;
    char line[64];
    while (fgets(line, sizeof(line), fp) && user_count < max_users) {
        int user_id = atoi(line);
        if (user_id >= 0) {
            snprintf(user_dirs[user_count], MAX_PATH_LEN, "%s/%d", USER_DATA_BASE_PATH, user_id);
            if (access(user_dirs[user_count], F_OK) == 0) {
                user_count++;
            }
        }
    }
    
    pclose(fp);
    return user_count;
}

// Fallback method: scan directory for numeric subdirectories
int get_users_from_directory_scan(char user_dirs[][MAX_PATH_LEN], int max_users) {
    DIR *dir = opendir(USER_DATA_BASE_PATH);
    if (!dir) {
        write_daemon_log("ERROR", 27, USER_DATA_BASE_PATH, strerror(errno));  // Cannot open directory
        // Fallback to user 0
        snprintf(user_dirs[0], MAX_PATH_LEN, "%s/0", USER_DATA_BASE_PATH);
        return 1;
    }
    
    int user_count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && user_count < max_users) {
        if (entry->d_type == DT_DIR) {
            char *endptr;
            long user_id = strtol(entry->d_name, &endptr, 10);
            if (*endptr == '\0' && strlen(entry->d_name) > 0 && user_id >= 0) {
                snprintf(user_dirs[user_count], MAX_PATH_LEN, "%s/%s", USER_DATA_BASE_PATH, entry->d_name);
                user_count++;
            }
        }
    }
    
    closedir(dir);
    
    // Ensure at least user 0 is included
    if (user_count == 0) {
        snprintf(user_dirs[0], MAX_PATH_LEN, "%s/0", USER_DATA_BASE_PATH);
        user_count = 1;
    }
    
    return user_count;
}

// Get list of user directories to scan
int get_user_directories(char user_dirs[][MAX_PATH_LEN], int max_users) {
    if (!config.multi_user_scan) {
        // Single user mode - scan only user 0
        snprintf(user_dirs[0], MAX_PATH_LEN, "%s/0", USER_DATA_BASE_PATH);
        return 1;
    }
    
    int user_count;
    
    // Method 1: Try to get user list from Android's package manager
    user_count = get_users_from_pm(user_dirs, max_users);
    if (user_count > 0) {
        return user_count;
    }
    
    // Method 2: Fallback - scan directory for numeric subdirectories
    return get_users_from_directory_scan(user_dirs, max_users);
}

// Free UID list memory
void free_uid_list(void) {
    struct uid_data *current = uid_list_head;
    while (current) {
        struct uid_data *next = current->next;
        free(current);
        current = next;
    }
    uid_list_head = NULL;
}

// Create new UID data entry
struct uid_data* create_uid_entry(int uid, const char *package_name) {
    struct uid_data *data = malloc(sizeof(struct uid_data));
    if (!data) {
        write_daemon_log("ERROR", 31);  // Memory allocation failed
        return NULL;
    }
    
    data->uid = uid;
    strncpy(data->package, package_name, MAX_PACKAGE_NAME - 1);
    data->package[MAX_PACKAGE_NAME - 1] = '\0';
    data->next = uid_list_head;
    return data;
}

// Scan single directory for packages
int scan_single_directory(const char *dir_path) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        write_daemon_log("ERROR", 27, dir_path, strerror(errno));  // Cannot open directory
        return 0;
    }
    
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (should_exit) break;
        
        // Skip special directories
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        if (entry->d_type != DT_DIR) {
            continue;
        }
        
        // Check package name length
        if (strlen(entry->d_name) >= MAX_PACKAGE_NAME) {
            write_daemon_log("WARN", 29, entry->d_name);  // Package name too long
            continue;
        }
        
        // Get file status
        char path[MAX_PATH_LEN];
        snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);
        
        struct stat st;
        if (stat(path, &st) != 0) {
            write_daemon_log("ERROR", 30, path, strerror(errno));  // Cannot get file status
            continue;
        }
        
        // Create and add UID entry
        struct uid_data *data = create_uid_entry(st.st_uid, entry->d_name);
        if (data) {
            uid_list_head = data;
            count++;
        }
    }
    
    closedir(dir);
    return count;
}

// Scan user data directories for UIDs
int scan_user_data_for_uids(void) {
    char user_dirs[MAX_USERS][MAX_PATH_LEN];
    int total_count = 0;
    
    // Clear existing UID list
    free_uid_list();
    
    // Get user directories to scan
    int user_count = get_user_directories(user_dirs, MAX_USERS);
    if (user_count <= 0) {
        return -1;
    }
    
    write_daemon_log("INFO", 28);  // Starting user data directory scan
    write_daemon_log("INFO", 63, user_count);  // Found X active users for scanning
    
    // Scan each user directory
    for (int i = 0; i < user_count && !should_exit; i++) {
        write_daemon_log("INFO", 62, user_dirs[i]);  // Scanning user directory
        total_count += scan_single_directory(user_dirs[i]);
    }
    
    write_daemon_log("INFO", 32, total_count);  // Scan completed, found X packages
    return total_count;
}

// Write UID whitelist to file
int write_uid_whitelist(void) {
    ensure_directory_exists();
    
    FILE *fp = fopen(KSU_UID_LIST_PATH, "w");
    if (!fp) {
        write_daemon_log("ERROR", 33, KSU_UID_LIST_PATH, strerror(errno));  // Cannot open whitelist file
        return -1;
    }
    
    int count = 0;
    struct uid_data *current = uid_list_head;
    while (current) {
        fprintf(fp, "%d %s\n", current->uid, current->package);
        current = current->next;
        count++;
    }
    
    fclose(fp);
    write_daemon_log("INFO", 34, count);  // Written X entries to UID whitelist
    return count;
}

// Notify kernel of update completion
void notify_kernel_update(void) {
    int fd = open(PROC_COMM_PATH, O_WRONLY);
    if (fd < 0) {
        write_daemon_log("ERROR", 35, PROC_COMM_PATH, strerror(errno));  // Cannot open kernel communication file
        return;
    }
    
    if (write(fd, "UPDATED", 7) != 7) {
        write_daemon_log("ERROR", 36, PROC_COMM_PATH, strerror(errno));  // Cannot write to kernel communication file
    } else {
        write_daemon_log("INFO", 37);  // Kernel update notification sent
    }
    
    close(fd);
}

// Check if kernel requested rescan
int check_kernel_request(void) {
    FILE *fp = fopen(PROC_COMM_PATH, "r");
    if (!fp) {
        return 0;  // File doesn't exist, normal condition
    }
    
    char status[16];
    int result = 0;
    if (fgets(status, sizeof(status), fp) != NULL) {
        result = (strncmp(status, "RESCAN", 6) == 0);
    }
    
    fclose(fp);
    return result;
}

// Perform complete scan and update operation
void perform_scan_update(void) {
    write_daemon_log("INFO", 38);  // Performing UID scan and update
    
    if (scan_user_data_for_uids() < 0) {
        write_daemon_log("ERROR", 39);  // UID scan failed
        return;
    }
    
    if (write_uid_whitelist() < 0) {
        write_daemon_log("ERROR", 40);  // Whitelist write failed
        return;
    }
    
    notify_kernel_update();
    write_daemon_log("INFO", 41);  // Scan and update completed successfully
}

// Print usage information
void print_usage(const char *prog) {
    if (config.language == LANG_ZH) {
        printf("用法: %s [选项]\n", prog);
        printf("KSU UID 扫描器 - 管理UID白名单\n\n");
        printf("选项:\n");
        printf("  start                启动守护进程\n");
        printf("  stop                 停止守护进程\n");
        printf("  restart              重启守护进程\n");
        printf("  status               显示守护进程状态\n");
        printf("  reload               重新加载守护进程配置\n");
        printf("  -s, --scan           执行一次扫描并退出\n");
        printf("  -l, --list           列出当前UID白名单\n");
        printf("  --lang <en|zh>       设置语言 (英文|中文)\n");
        printf("  --multi-user <0|1>   设置多用户扫描 (0=禁用, 1=启用)\n");
        printf("  --config             显示当前配置\n");
        printf("  -h, --help           显示此帮助信息\n");
        printf("\n守护进程管理:\n");
        printf("  %s start             # 启动后台守护进程\n", prog);
        printf("  %s stop              # 停止守护进程\n", prog);
        printf("  %s status            # 查看运行状态\n", prog);
        printf("  %s --lang zh         # 切换到中文界面\n", prog);
        printf("  %s --multi-user 1    # 启用多用户扫描\n", prog);
    } else {
        printf("Usage: %s [options]\n", prog);
        printf("KSU UID Scanner - Manage UID whitelist\n\n");
        printf("Options:\n");
        printf("  start                Start daemon process\n");
        printf("  stop                 Stop daemon process\n");
        printf("  restart              Restart daemon process\n");
        printf("  status               Show daemon status\n");
        printf("  reload               Reload daemon configuration\n");
        printf("  -s, --scan           Perform one scan and exit\n");
        printf("  -l, --list           List current UID whitelist\n");
        printf("  --lang <en|zh>       Set language (English|Chinese)\n");
        printf("  --multi-user <0|1>   Set multi-user scanning (0=disabled, 1=enabled)\n");
        printf("  --config             Show current configuration\n");
        printf("  -h, --help           Show this help message\n");
        printf("\nDaemon management:\n");
        printf("  %s start             # Start background daemon\n", prog);
        printf("  %s stop              # Stop daemon\n", prog);
        printf("  %s status            # Check running status\n", prog);
        printf("  %s --lang en         # Switch to English interface\n", prog);
        printf("  %s --multi-user 1    # Enable multi-user scanning\n", prog);
    }
}

// List current whitelist contents
void list_whitelist(void) {
    FILE *fp = fopen(KSU_UID_LIST_PATH, "r");
    if (!fp) {
        printf(get_message(42), strerror(errno));  // Whitelist file not found or open failed
        printf("\n");
        return;
    }
    
    printf("%s\n", get_message(43));  // Current UID whitelist
    printf("%-8s %-40s\n", "UID", (config.language == LANG_ZH) ? "包名" : "Package");
    printf("%-8s %-40s\n", "--------", "----------------------------------------");
    
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        int uid;
        char package[256];
        if (sscanf(line, "%d %255s", &uid, package) == 2) {
            printf("%-8d %-40s\n", uid, package);
        }
    }
    
    fclose(fp);
}

// Show current configuration
void show_config(void) {
    if (config.language == LANG_ZH) {
        printf("当前配置:\n");
        printf("  语言: %s\n", (config.language == LANG_ZH) ? "中文" : "英文");
        printf("  多用户扫描: %s\n", config.multi_user_scan ? "启用" : "禁用");
        printf("  扫描间隔: %d 秒\n", config.scan_interval);
        printf("  日志级别: %d\n", config.log_level);
    } else {
        printf("Current Configuration:\n");
        printf("  Language: %s\n", (config.language == LANG_ZH) ? "Chinese" : "English");
        printf("  Multi-user scan: %s\n", config.multi_user_scan ? "Enabled" : "Disabled");
        printf("  Scan interval: %d seconds\n", config.scan_interval);
        printf("  Log level: %d\n", config.log_level);
    }
}

// Handle configuration commands
int handle_config_command(int argc, char *argv[]) {
    if (strcmp(argv[1], "--lang") == 0) {
        if (argc < 3) {
            printf("Language not specified\n");
            return 1;
        }
        if (strcmp(argv[2], "zh") == 0) {
            set_language(LANG_ZH);
        } else if (strcmp(argv[2], "en") == 0) {
            set_language(LANG_EN);
        } else {
            printf("Invalid language: %s (use 'en' or 'zh')\n", argv[2]);
            return 1;
        }
        return 0;
    } else if (strcmp(argv[1], "--multi-user") == 0) {
        if (argc < 3) {
            printf("Multi-user setting not specified\n");
            return 1;
        }
        int value = atoi(argv[2]);
        if (value != 0 && value != 1) {
            printf("Invalid multi-user setting: %s (use 0 or 1)\n", argv[2]);
            return 1;
        }
        set_multi_user_scan(value);
        return 0;
    } else if (strcmp(argv[1], "--config") == 0) {
        show_config();
        return 0;
    }
    return -1;  // Command not handled
}

// Handle single execution commands
int handle_single_command(int argc, char *argv[]) {
    (void)argc;
    if (strcmp(argv[1], "-s") == 0 || strcmp(argv[1], "--scan") == 0) {
        printf("%s\n", get_message(44));  // Performing one-time scan
        perform_scan_update();
        return 0;
    } else if (strcmp(argv[1], "-l") == 0 || strcmp(argv[1], "--list") == 0) {
        list_whitelist();
        return 0;
    } else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    } else if (strcmp(argv[1], "status") == 0) {
        show_status();
        return 0;
    } else if (strcmp(argv[1], "stop") == 0) {
        return stop_daemon();
    } else if (strcmp(argv[1], "reload") == 0) {
        reload_daemon();
        return 0;
    }
    return -1;  // Command not handled
}

// Setup signal handlers for daemon
void setup_signal_handlers(void) {
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGHUP, signal_handler);
    signal(SIGUSR1, signal_handler);
    signal(SIGPIPE, SIG_IGN);  // Ignore pipe signal
}

// Initialize daemon logging
void init_daemon_logging(void) {
    ensure_directory_exists();
    log_fd = open(LOG_FILE_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
}

// Cleanup daemon resources
void cleanup_daemon_resources(void) {
    write_daemon_log("INFO", 52);  // Daemon is exiting
    
    // Free UID list memory
    free_uid_list();
    
    // Remove PID file
    unlink(PID_FILE_PATH);
    
    // Close log file
    if (log_fd != -1) {
        close(log_fd);
    }
    
    write_daemon_log("INFO", 53);  // UID Scanner daemon exited
}

// Main daemon loop with periodic scanning
void run_daemon_loop(void) {
    write_daemon_log("INFO", 49);  // UID Scanner daemon started
    
    // Perform initial scan
    perform_scan_update();
    
    // Main daemon loop
    while (!should_exit) {
        // Handle reload requests
        if (should_reload) {
            write_daemon_log("INFO", 50);  // Received reload request
            perform_scan_update();
            should_reload = 0;
        }
        
        // Check kernel requests
        if (check_kernel_request()) {
            write_daemon_log("INFO", 51);  // Kernel requested rescan
            perform_scan_update();
        }
        
        // Manage log file size
        manage_log_file();
        
        // Sleep for configured interval, checking exit condition frequently
        int sleep_iterations = config.scan_interval * 10;
        for (int i = 0; i < sleep_iterations && !should_exit && !should_reload; i++) {
            usleep(100000);  // 0.1 second
        }
    }
}

// Main function
int main(int argc, char *argv[]) {
    // Load configuration
    load_config();
    
    // Show usage if no arguments
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    // Handle configuration commands
    int result = handle_config_command(argc, argv);
    if (result >= 0) {
        return result;
    }
    
    // Handle single execution commands
    result = handle_single_command(argc, argv);
    if (result >= 0) {
        return result;
    }
    
    // Handle daemon commands
    if (strcmp(argv[1], "restart") == 0) {
        if (restart_daemon() != 0) {
            return 1;
        }
        // Continue to daemon startup
    } else if (strcmp(argv[1], "start") != 0) {
        printf(get_message(45), argv[1]);  // Invalid argument
        printf("\n");
        print_usage(argv[0]);
        return 1;
    }
    
    // Check if daemon is already running
    if (is_daemon_running()) {
        printf("%s\n", get_message(46));  // Daemon already running
        return 1;
    }
    
    // Start daemon process
    printf("%s\n", get_message(47));  // Starting daemon process
    if (daemonize() != 0) {
        printf("%s\n", get_message(48));  // Daemon startup failed
        return 1;
    }
    
    // Initialize daemon environment
    init_daemon_logging();
    
    if (write_pid_file() != 0) {
        exit(1);
    }
    
    setup_signal_handlers();
    
    // Run main daemon loop
    run_daemon_loop();
    
    // Cleanup and exit
    cleanup_daemon_resources();
    return 0;
}