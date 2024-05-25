#include "asiomp.h"

#include "session.h"

extern char** environ;

static char* cpystrn(char* dst, const char* src, size_t n) {
    if (n == 0) {
        return dst;
    }

    while (--n) {
        *dst = *src;
        if (*dst == '\0') {
            return dst;
        }

        dst++;
        src++;
    }

    *dst = '\0';

    return dst;
}

asiomp_server::asiomp_server(char** argv, const std::string& host,
                             uint16_t port)
    : os_argv(argv),
      os_argv_last(argv[0]),
      io_context(1),
      signals(io_context),
      acceptor(io_context),
      listen_endpoint(asio::ip::make_address(host), port),
      single_mode(true),
      isworker(false),
      terminate(false) {}

asiomp_server::asiomp_server(char** argv, const std::string& host,
                             uint16_t port, uint32_t worker_num)
    : os_argv(argv),
      os_argv_last(argv[0]),
      io_context(1),
      signals(io_context),
      acceptor(io_context),
      listen_endpoint(asio::ip::make_address(host), port),
      single_mode(false),
      isworker(false),
      terminate(false),
      processes(worker_num) {}

asiomp_server::~asiomp_server() { spdlog::shutdown(); }

void asiomp_server::run() noexcept {
    try {
        this->init();

        if (this->single_mode) {
            this->worker_process();
        } else {
            this->spawn_process();
            this->io_context.run();
        }
    } catch (std::exception& e) {
        SPDLOG_ERROR("asiomp server failed to run : {}", std::string(e.what()));
    }
}

void asiomp_server::stop_server() { this->io_context.stop(); }

void asiomp_server::init() {
    this->init_setproctitle();
    this->set_proctitle("master process");

    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;

    char buffer[80];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d_%H-%M-%S",
                  std::localtime(&time));
    ss << buffer;
    this->log_dir = "logs/" + ss.str() + "/";

    this->set_logger("asiomp_master");

    this->signals.add(SIGINT);
    this->signals.add(SIGTERM);
    this->signals.add(SIGCHLD);

    this->signal_handler();

    this->acceptor.open(this->listen_endpoint.protocol());
    this->acceptor.set_option(asio::ip::tcp::acceptor::reuse_address(true));
    this->acceptor.bind(this->listen_endpoint);
    this->acceptor.listen();
}

void asiomp_server::init_setproctitle() {
    size_t size = 0;

    for (int i = 0; environ[i]; i++) {
        size += strlen(environ[i]) + 1;
    }

    this->os_environ.reset(new char[size]);

    for (int i = 0; this->os_argv[i]; i++) {
        if (this->os_argv_last == this->os_argv[i]) {
            this->os_argv_last =
                this->os_argv[i] + strlen(this->os_argv[i]) + 1;
        }
    }

    char* p = this->os_environ.get();

    for (int i = 0; environ[i]; i++) {
        if (this->os_argv_last == environ[i]) {
            size = strlen(environ[i]) + 1;
            this->os_argv_last = environ[i] + size;

            cpystrn(p, environ[i], size);
            environ[i] = p;

            p += size;
        }
    }

    this->os_argv_last--;
}

void asiomp_server::set_proctitle(const std::string& title) {
    char* p = nullptr;

    this->os_argv[1] = nullptr;

    p = cpystrn(this->os_argv[0], ASIOMP_PROC_NAME,
                this->os_argv_last - this->os_argv[0]);

    p = cpystrn(p, ": ", this->os_argv_last - p);
    p = cpystrn(p, title.c_str(), this->os_argv_last - p);

    if (this->os_argv_last - p) {
        memset(p, '\0', this->os_argv_last - p);
    }
}

void asiomp_server::set_logger(const std::string& logger_name) {
    std::string log_file =
        this->log_dir + logger_name + "-" + std::to_string(getpid()) + ".log";

    if (this->isworker) {
        spdlog::init_thread_pool(8192, 1);

        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            log_file, 1048576 * 5, 3);

        spdlog::set_default_logger(std::make_shared<spdlog::async_logger>(
            logger_name, file_sink, spdlog::thread_pool(),
            spdlog::async_overflow_policy::block));
    } else {
        auto file_logger =
            spdlog::rotating_logger_st(logger_name, log_file, 1048576 * 5, 3);

        spdlog::set_default_logger(file_logger);
    }

    spdlog::set_pattern("[%Y-%m-%d %T.%f] [thread %t] [%^%l%$] %v");

    switch (SPDLOG_ACTIVE_LEVEL) {
        case SPDLOG_LEVEL_TRACE:
            spdlog::set_level(spdlog::level::trace);
            break;
        case SPDLOG_LEVEL_DEBUG:
            spdlog::set_level(spdlog::level::debug);
            break;
        case SPDLOG_LEVEL_INFO:
            spdlog::set_level(spdlog::level::info);
            break;
        case SPDLOG_LEVEL_WARN:
            spdlog::set_level(spdlog::level::warn);
            break;
        case SPDLOG_LEVEL_ERROR:
            spdlog::set_level(spdlog::level::err);
            break;
        case SPDLOG_LEVEL_CRITICAL:
            spdlog::set_level(spdlog::level::critical);
            break;
        case SPDLOG_LEVEL_OFF:
            spdlog::set_level(spdlog::level::off);
            break;
        default:
            break;
    }
}

void asiomp_server::signal_handler() {
    this->signals.async_wait([this](asio::error_code ec, int sig) {
        if (ec) {
            return;
        }

        this->signal_handler();

        switch (sig) {
            case SIGINT:
            case SIGTERM: {
                this->terminate = true;

                if (!this->isworker) {
                    this->stop_worker();
                }

                this->stop_server();

                break;
            }
            case SIGCHLD: {
                this->update_status();

                if (!this->terminate) {
                    this->reap_worker();
                }

                break;
            }
            default: {
                break;
            }
        }
    });
}

void asiomp_server::spawn_process() {
    int n = processes.size();

    for (int i = 0; i < n; i++) {
        int idx = -1;

        for (int j = 0; j < n; j++) {
            if (this->processes[j].pid == -1) {
                idx = j;
                break;
            }
        }

        if (idx == -1) {
            break;
        }

        this->spawn_process(idx);
    }
}

void asiomp_server::spawn_process(int respawn) {
    this->io_context.notify_fork(asio::io_context::fork_prepare);
    pid_t pid = fork();

    switch (pid) {
        case -1: {
            return;
        }
        case 0: {
            this->io_context.notify_fork(asio::io_context::fork_child);
            this->isworker = true;
            this->set_proctitle("worker process");
            this->set_logger("asiomp_worker");
            this->worker_process();
            break;
        }
        default: {
            this->io_context.notify_fork(asio::io_context::fork_parent);
            break;
        }
    }

    processes[respawn].pid = pid;
    processes[respawn].exited = false;
}

void asiomp_server::handle_accept() {
    this->acceptor.async_accept(
        [this](asio::error_code ec, asio::ip::tcp::socket socket) {
            if (!ec) {
                std::make_shared<session>(std::move(socket))->start();
            } else {
                SPDLOG_WARN("failed to accept : {}", ec.value());
            }

            this->handle_accept();
        });
}

void asiomp_server::worker_process() {
    this->handle_accept();
    this->io_context.run();

    if (this->isworker) {
        spdlog::shutdown();
        exit(EXIT_SUCCESS);
    }
}

void asiomp_server::stop_worker() {
    for (auto& p : this->processes) {
        if (p.pid == -1) {
            continue;
        }

        kill(p.pid, SIGTERM);
    }
}

void asiomp_server::update_status() {
    for (;;) {
        int status;
        pid_t pid = waitpid(-1, &status, WNOHANG);

        if (pid == 0) {
            return;
        }

        if (pid == -1) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }

        for (auto& p : this->processes) {
            if (p.pid == pid) {
                p.exited = true;
            }
        }
    }
}

void asiomp_server::reap_worker() {
    int n = this->processes.size();

    for (int idx = 0; idx < n; idx++) {
        if (this->processes[idx].pid == -1) {
            continue;
        }

        if (this->processes[idx].exited) {
            this->spawn_process(idx);
        }
    }
}