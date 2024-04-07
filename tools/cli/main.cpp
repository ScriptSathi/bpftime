#include "spdlog/spdlog.h"
#include "spdlog/cfg/env.h"
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <frida-core.h>
#include <argparse/argparse.hpp>
#include <filesystem>
#include <stdexcept>
#include <string_view>
#include <unistd.h>
#include <vector>
#include <string>
#include <utility>
#include <sys/wait.h>
#include "command.hpp"

static int subprocess_pid = 0;

static bool str_starts_with(const char *main, const char *pat)
{
	if (strstr(main, pat) == main)
		return true;
	return false;
}

static int run_command(const char *path, const std::vector<std::string> &argv,
		       const char *ld_preload, const char *agent_so)
{
	int pid = fork();
	if (pid == 0) {
		std::string ld_preload_str("LD_PRELOAD=");
		std::string agent_so_str("AGENT_SO=");
		ld_preload_str += ld_preload;

		if (agent_so) {
			agent_so_str += agent_so;
		}
		std::vector<const char *> env_arr;
		char **p = environ;
		while (*p) {
			env_arr.push_back(*p);
			p++;
		}
		bool ld_preload_set = false, agent_so_set = false;
		for (auto &s : env_arr) {
			if (str_starts_with(s, "LD_PRELOAD=")) {
				s = ld_preload_str.c_str();
				ld_preload_set = true;
			} else if (str_starts_with(s, "AGENT_SO=")) {
				s = agent_so_str.c_str();
				agent_so_set = true;
			}
		}
		if (!ld_preload_set)
			env_arr.push_back(ld_preload_str.c_str());
		if (!agent_so_set)
			env_arr.push_back(agent_so_str.c_str());

		env_arr.push_back(nullptr);
		std::vector<const char *> argv_arr;
		argv_arr.push_back(path);
		for (const auto &str : argv)
			argv_arr.push_back(str.c_str());
		argv_arr.push_back(nullptr);
		execvpe(path, (char *const *)argv_arr.data(),
			(char *const *)env_arr.data());
	} else {
		subprocess_pid = pid;
		int status;
		if (int cid = waitpid(pid, &status, 0); cid > 0) {
			if (WIFEXITED(status)) {
				int exit_code = WEXITSTATUS(status);
				if (exit_code != 0) {
					spdlog::error(
						"Program exited abnormally: {}",
						exit_code);
					return 1;
				}
			}
		}
	}
	return 1;
}
static int inject_by_frida(int pid, const char *inject_path, const char *arg)
{
	spdlog::info("Injecting to {}", pid);
	frida_init();
	auto injector = frida_injector_new();
	GError *err = nullptr;
	auto id = frida_injector_inject_library_file_sync(injector, pid,
							  inject_path,
							  "bpftime_agent_main",
							  arg, nullptr, &err);
	if (err) {
		spdlog::error("Failed to inject: {}", err->message);
		g_error_free(err);
		frida_unref(injector);
		frida_deinit();
		return 1;
	}
	spdlog::info("Successfully injected. ID: {}", id);
	frida_injector_close_sync(injector, nullptr, nullptr);
	frida_unref(injector);
	frida_deinit();
	return 0;
}

static std::pair<std::string, std::vector<std::string> >
extract_path_and_args(const argparse::ArgumentParser &parser)
{
	std::vector<std::string> items;
	try {
		items = parser.get<std::vector<std::string> >("COMMAND");
	} catch (std::logic_error &err) {
		std::cerr << parser;
		exit(1);
	}
	std::string executable = items[0];
	items.erase(items.begin());
	return { executable, items };
}

static void signal_handler(int sig)
{
	if (subprocess_pid) {
		kill(subprocess_pid, sig);
	}
}

static int do_load(Command *cmd) {
	auto so_path = cmd->get_install_path() / "libbpftime-syscall-server.so";
		if (!std::filesystem::exists(so_path)) {
			spdlog::error("Library not found: {}", so_path.c_str());
			return EXIT_FAILURE;
		}
		auto [executable_path, extra_args] =
			extract_path_and_args(cmd->load_command);
		return run_command(executable_path.c_str(), extra_args,
				   so_path.c_str(), nullptr);
}

static int do_start(Command *cmd) {
	std::filesystem::path install_path = cmd->get_install_path();
	auto agent_path = install_path / "libbpftime-agent.so";
	if (!std::filesystem::exists(agent_path)) {
		spdlog::error("Library not found: {}", agent_path.c_str());
		return EXIT_FAILURE;
	}
	auto [executable_path, extra_args] =
		extract_path_and_args(cmd->start_command);
	if (cmd->start_command.get<bool>("enable-syscall-trace")) {
		auto transformer_path =
			install_path /
			"libbpftime-agent-transformer.so";
		if (!std::filesystem::exists(transformer_path)) {
			spdlog::error("Library not found: {}", transformer_path.c_str());
			return EXIT_FAILURE;
		}

		return run_command(executable_path.c_str(), extra_args,
					transformer_path.c_str(),
					agent_path.c_str());
	} else {
		return run_command(executable_path.c_str(), extra_args,
					agent_path.c_str(), nullptr);
	}
}

static int do_attach(Command *cmd) {
	std::filesystem::path install_path = cmd->get_install_path();
	auto agent_path = install_path / "libbpftime-agent.so";
	if (!std::filesystem::exists(agent_path)) {
		spdlog::error("Library not found: {}",
					agent_path.c_str());
		return EXIT_FAILURE;
	}
	auto pid = cmd->attach_command.get<int>("PID");
	if (cmd->attach_command.get<bool>("enable-syscall-trace")) {
		auto transformer_path =
			install_path /
			"libbpftime-agent-transformer.so";
		if (!std::filesystem::exists(transformer_path)) {
			spdlog::error("Library not found: {}",
						transformer_path.c_str());
			return EXIT_FAILURE;
		}
		return inject_by_frida(pid, transformer_path.c_str(),
							agent_path.c_str());
	} else {
		return inject_by_frida(pid, agent_path.c_str(), "");
	}
}

int main(int argc, const char **argv)
{
	spdlog::cfg::load_env_levels();
	signal(SIGINT, signal_handler);
	signal(SIGTSTP, signal_handler);

	Command cmd(argv[0]);

	if (!cmd.is_parsing_valid(argc, argv)) {
		std::cerr << cmd.root_program;
		return EXIT_FAILURE;
	}

	switch (cmd.get_command_type()) {
		case Command::Type::Load: {
			return do_load(&cmd);
		}
		case Command::Type::Start: {
			return do_start(&cmd);
		}
		case Command::Type::Attach: {
			return do_attach(&cmd);
		}
		case Command::Type::None:
		default: {
			return EXIT_FAILURE;
		}
	}
}
