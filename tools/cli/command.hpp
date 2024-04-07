#ifndef COMMAND_H
#define COMMAND_H

#include <argparse/argparse.hpp>
#include <filesystem>
#include <string>

class Command {
public:
   explicit Command(const std::string cmd_name);
   enum class Type {
      None,
      Load,
      Start,
      Attach
   };
   bool is_parsing_valid(int argc, const char **argv);
   std::filesystem::path get_install_path();
   Type get_command_type();
   argparse::ArgumentParser root_program;
   argparse::ArgumentParser load_command;
   argparse::ArgumentParser start_command;
   argparse::ArgumentParser attach_command;

private:
   void add_root_arguments();
   void add_load_command();
   void add_start_command();
   void add_attach_command();
};

#endif