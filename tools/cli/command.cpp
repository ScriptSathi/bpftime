#include "spdlog/spdlog.h"
#include <cstdlib>
#include <frida-core.h>
#include <argparse/argparse.hpp>
#include <filesystem>
#include <string_view>
#include <unistd.h>
#include <string>
#include <sys/wait.h>
#include "command.hpp"

Command::Command(const std::string cmd_name) :
   root_program(argparse::ArgumentParser(cmd_name)),
   load_command(argparse::ArgumentParser("load")),
   start_command(argparse::ArgumentParser("start")),
   attach_command(argparse::ArgumentParser("attach")) {
   add_root_arguments();
   add_load_command();
   add_start_command();
   add_attach_command();
}

Command::Type Command::get_command_type() {
   if (root_program.is_subcommand_used("load")) return Type::Load;
   if (root_program.is_subcommand_used("start")) return Type::Start;
   if (root_program.is_subcommand_used("attach")) return Type::Attach;
   return Type::None;
}

bool Command::is_parsing_valid(int argc, const char **argv) {
   try {
      root_program.parse_args(argc, argv);
      return true;
   } catch (const std::exception &err) {
      std::cerr << err.what() << std::endl;
      return false;
   }
}

std::filesystem::path Command::get_install_path() {
   return std::filesystem::path(root_program.get("install-location"));
}

void Command::add_root_arguments() {
   if (auto home_env = getenv("HOME"); home_env) {
      std::string default_location(home_env);
      default_location += "/.bpftime";
      root_program.add_argument("-i", "--install-location")
         .help("Installing location of bpftime")
         .default_value(default_location)
         .required()
         .nargs(1);
   } else {
      spdlog::warn("Unable to determine home directory. You must specify --install-location");
      root_program.add_argument("-i", "--install-location")
         .help("Installing location of bpftime")
         .required()
         .nargs(1);
   }

   root_program.add_argument("-d", "--dry-run")
      .help("Run without committing any modifications")
      .flag();
}

void Command::add_load_command() {
   load_command.add_description("Start an application with bpftime-server injected");
   load_command.add_argument("COMMAND")
      .help("Command to run")
      .nargs(argparse::nargs_pattern::at_least_one)
      .remaining();
   root_program.add_subparser(load_command);
}

void Command::add_start_command() {
   start_command.add_description("Start an application with bpftime-agent injected");
   start_command.add_argument("-s", "--enable-syscall-trace")
      .help("Whether to enable syscall trace")
      .flag();
   start_command.add_argument("COMMAND")
      .nargs(argparse::nargs_pattern::at_least_one)
      .remaining()
      .help("Command to run");
   root_program.add_subparser(start_command);
}

void Command::add_attach_command() {
   attach_command.add_description("Inject bpftime-agent to a certain pid");
   attach_command.add_argument("-s", "--enable-syscall-trace")
      .help("Whether to enable syscall trace")
      .flag();
   attach_command.add_argument("PID")
      .scan<'i', int>();
   root_program.add_subparser(attach_command);
}
