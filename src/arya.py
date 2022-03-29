import argparse
import subprocess
import os
import re
import random
import binascii
import sys
import base64
from pathlib import Path

import colorama
import yaramod as ym

from file_mapper import FileMapper
from ast_observer import YaraAstObserver


class RuleReverser:
    def __init__(self, input_path, output_path, is_recursive, add_pe_header, malware_file):
        self._curr_indent = 0
        self._file_mapper = FileMapper(add_pe_header, malware_file)
        self._input_path = input_path
        self._input_files_paths, self._rules_list = self.get_rules_list(self._input_path, is_recursive)
        self._output_file_path = output_path
        self.all_offsets = []
        self.rules_names = []
        self.print_row("[-] Starting Arya")

    def increase_indent(self):
        self._curr_indent += 4

    def decrease_indent(self):
        self._curr_indent -= 4

    def print_row(self, string):
        print((self._curr_indent * ' ') + string)

    def _hex_string_to_bytes(self, string):
        ret_str = str(string.text)

        ret_str = ret_str.replace("{", "").replace("}", "") \
            .replace("??", "90").replace("?", "0").replace(" ", "").strip()

        amounts_to_replace = re.findall("(\[(\d*)[\-\][\d]*])", ret_str)
        if amounts_to_replace:
            for sub_to_replace, amount in amounts_to_replace:
                if not amount:
                    amount = 1
                sub_to_replace = "\\" + sub_to_replace[:-1] + "\\" + sub_to_replace[-1]
                ret_str = re.sub(sub_to_replace, "90" * int(amount), ret_str)

        groups_to_replace = re.findall("(\(([0-9A-F]*)\|)", ret_str)
        if groups_to_replace:
            for sub_to_replace, hex_stream in groups_to_replace:
                sub_to_replace = "\\" + sub_to_replace[:-1] + "\|[0-9A-F|]*?\)"
                ret_str = re.sub(sub_to_replace, hex_stream, ret_str)

        return binascii.unhexlify(ret_str)

    def _yara_string_to_bytes(self, string):
        if string.is_plain:
            if string.is_base64:
                print(string)
                return base64.b64encode(string.pure_text)
            if string.is_base64_wide:
                return str(base64.b64encode(string.pure_text)).encode("utf-16")
            if string.is_wide:
                return str(string.pure_text).encode("utf-16")
            if string.is_ascii:
                return string.pure_text
        if string.is_hex:
            return self._hex_string_to_bytes(string)
        if string.is_regexp:
            pass

    def _of_expr_to_string(self, count, iterable, string_mapping):
        if isinstance(iterable, ym.ThemExpression):
            strings = string_mapping
        elif isinstance(iterable, ym.SetExpression):
            elements = [element.id.replace("$", "\\$").replace("*", ".*") for element in iterable.elements]
            strings = {key: val for key, val in string_mapping.items() if
                       any([re.findall(element, key) for element in elements])}
        else:
            return None

        if count.get_text() == "all":
            amount = len(strings)
        elif count.get_text() == "any":
            amount = 1
        else:
            amount = int(count.get_text())

        return b"".join([self._yara_string_to_bytes(val) for val in list(strings.values())][:amount])

    def get_rules_list(self, path, is_recursive):
        ymod_parser = ym.Yaramod()

        all_file_paths = []
        if os.path.isdir(path):
            if is_recursive:
                all_file_paths = [str(p) for p in list(Path(path).rglob("*.[yY][aA][rR]"))]
            else:
                for root, subdirectories, files in os.walk(path):
                    for file in files:
                        all_file_paths.append(os.path.join(root, file))
        elif os.path.isfile(path):
            all_file_paths.append(path)

        all_yara_rules = []
        for file_path in all_file_paths:
            curr_yar_file = ymod_parser.parse_file(file_path)
            all_yara_rules.extend([(rule, file_path) for rule in curr_yar_file.rules])

        self.print_row(f"[-] Input file/directory {self._input_path}, found {len(all_yara_rules)} yara rules")
        return all_file_paths, all_yara_rules

    def init_offset_list(self):
        for rule, path in self._rules_list:
            ast_observer = YaraAstObserver(self._file_mapper)
            self.rules_names.append((rule.name, path))
            string_mapping = {s.identifier: s for s in rule.strings}
            ast_observer.observe(rule.condition)
            offsets_map = ast_observer.strings_offsets_map
            for expr in offsets_map:
                if expr["operation"] == "of":
                    expr["var"] = self._of_expr_to_string(expr["min_offset"], expr["max_offset"], string_mapping)
                    expr["operation"] = "String"
                    expr["min_offset"] = "*"
                    expr["max_offset"] = "*"
                elif expr["operation"] == "IntFunction":
                    continue
                else:
                    expr["var"] = self._yara_string_to_bytes(string_mapping[expr["var"]])
            self.all_offsets.extend(offsets_map)

    def build_file_from_instructions(self):
        free_strings = b""

        self.print_row("[-] Building output file...")
        for instructions_dict in self.all_offsets:
            if (instructions_dict["operation"] == "String"
                    and instructions_dict["min_offset"] == instructions_dict["max_offset"] == "*"):
                free_strings += b"." + instructions_dict["var"] + b"." \
                                + self._file_mapper.generate_random_x86_code(random.randint(1, 16))
            elif instructions_dict["operation"] == "IntFunction":
                self._file_mapper.place(instructions_dict["var"], int(instructions_dict["min_offset"]), pre_reserved=True)
            elif instructions_dict["operation"] == "at":
                min_offset = instructions_dict["min_offset"]
                if "entrypoint" in min_offset:
                    continue
                self._file_mapper.place(instructions_dict["var"], int(min_offset))

        random_amount_of_code = self._file_mapper.generate_random_x86_code(random.randint(1024, self._file_mapper.get_file_len()))
        self._file_mapper.append(random_amount_of_code)
        self._file_mapper.append(free_strings)
        self._file_mapper.fill_empty_with_code()

        self.print_row(f"[-] Saving result to {self._output_file_path}")
        with open(self._output_file_path, "wb") as out:
            out.write(self._file_mapper.get_as_bytestream())

        return self._file_mapper.get_as_bytestream()

    def test_yara(self, rules_path):
        yara_output = subprocess.run(['yara', rules_path, self._output_file_path], stdout=subprocess.PIPE).stdout.decode('utf-8')
        return [out.split(" ")[0] for out in yara_output.split("\n")]

    def print_triggered_and_summary(self):
        triggered_rules = []
        for in_path in self._input_files_paths:
            triggered_rules.extend([rule for rule in self.test_yara(in_path) if rule])
        self.print_row("[-] Checking result output against all files")
        self.increase_indent()
        for rule, file in self.rules_names:
            if rule in triggered_rules:
                self.print_row(f"File {file} Rule {rule}: {colorama.Fore.LIGHTGREEN_EX}Triggered")
            else:
                self.print_row(f"File {file} Rule {rule}: {colorama.Fore.RED}Not triggered")
        self.decrease_indent()
        self.print_row("\n[-] Summary:")

        self.increase_indent()
        self.print_row(f"[-] File {self._output_file_path} size in kb: {round(self._file_mapper.get_file_len() / 1024, 2)}")
        self.print_row(f"[-] Number of rules triggered: {len(triggered_rules)}/{len(self.rules_names)} rules")
        self.decrease_indent()

        self.print_row("\n[-] Done.")

def main():
    colorama.init(autoreset=True)
    parser = argparse.ArgumentParser(
        description="Build a file that will trigger as much yara rules as possible from a given directory/file.")
    if len(sys.argv) < 3:
        parser.print_help()
    parser.add_argument("-i", dest="in_path", type=str, required=True,
                        help="PATH_TO_FILE or PATH_TO_DIRECTORY")
    parser.add_argument("-o", dest="out_path", type=str, required=True,
                        help="OUTPUT_FILE_PATH")
    parser.add_argument("-m", dest="malware_file", type=str, required=False,
                        help="MALWARE_FILE - Malware/Executable file to use as template")
    parser.add_argument("--header", dest="add_pe_header", action="store_true", required=False,
                        help="Adds the pe header(first 2048 bytes) of MALWARE_FILE in the beginning of the file. "
                             "If no malware file is specified, adds from conficker.")
    parser.add_argument("-r", dest="is_recursive", action="store_true", required=False,
                        help="Recursively scan all sub folders of input path for .yar files")
    args = parser.parse_args()

    rule_reverser = RuleReverser(args.in_path, args.out_path, args.is_recursive, args.add_pe_header, args.malware_file)
    rule_reverser.init_offset_list()
    rule_reverser.build_file_from_instructions()
    rule_reverser.print_triggered_and_summary()


if __name__ == "__main__":
    main()
