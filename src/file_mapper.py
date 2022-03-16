import random

from consts import CONFICKER_FIRST_4KB

PE_HEADER_OFFSET = 2048

def _add_func_pre_and_epi(func):
    # function Prologue Example
    # 55 89 e5 83 ec 0c
    # 0:  55                      push   ebp
    # 1:  89 e5                   mov    ebp,esp
    # 3:  83 ec 0c                sub    esp,0xc

    # function Epilogue Example
    # 89 ec 5d c3
    # 0:  89 ec                   mov    esp,ebp
    # 2:  5d                      pop    ebp
    # 3:  c3                      ret
    def inner(self, length):
        if length > 10:
            start = b"\x55\x89\xe5\x83\xec" + (4 * random.randint(1, 30)).to_bytes(1, byteorder="little", signed=True)
            end = b"\x89\xec\x5d\xc3"
            return start + func(self, length)[len(start):-1 * len(end)] + end
        else:
            return func(self, length)
    return inner

class FileMapper:
    def __init__(self, add_pe_header, malware_file):
        self._byte_mapping = []
        self._read_malware(malware_file)
        if add_pe_header:
            self._get_pe_header()

    def is_slice_empty(self, start_index, end_index):
        if len(self._byte_mapping) < end_index:
            self._byte_mapping += [None] * (end_index - len(self._byte_mapping))

        return all([True if byte is None else False for byte in self._byte_mapping[start_index:end_index]])

    def is_slice_reserved(self, start_index, end_index):
        return all([True if place == "reserved" else False for place in self._byte_mapping[start_index:end_index]])

    def place(self, byte_string, start_index, pre_reserved=False):
        end_index = start_index + len(byte_string)
        if self.is_slice_empty(start_index, end_index) or (pre_reserved and self.is_slice_reserved(start_index, end_index)):
            self._byte_mapping = self._byte_mapping[:start_index] + list(byte_string) + self._byte_mapping[end_index:]

    def append(self, byte_string):
        self._byte_mapping.extend(byte_string)

    def _get_first_free_spot(self, length):
        for curr_index, value in enumerate(self._byte_mapping):
            if self.is_slice_empty(curr_index, curr_index + length):
                return curr_index
        return len(self._byte_mapping)

    def reserve_first_free_spot(self, length):
        first_free_index = self._get_first_free_spot(length)
        self._byte_mapping = self._byte_mapping[:first_free_index] + (["reserved"] * length) + self._byte_mapping[first_free_index + length:]
        return first_free_index

    def _get_pe_header(self):
        self.append(self._malware_bytes[:PE_HEADER_OFFSET])

    def _read_malware(self, file_name):
        if file_name:
            with open(file_name, "rb") as malware_file:
                self._malware_bytes = malware_file.read()
        else:
            self._malware_bytes = CONFICKER_FIRST_4KB

    @_add_func_pre_and_epi
    def generate_random_x86_code(self, length):
        if self.get_malware_len() - PE_HEADER_OFFSET < length:
            start_index = random.randint(PE_HEADER_OFFSET, self.get_malware_len() - 1)
            mult = length // (self.get_malware_len() - start_index) + 1
            return (self._malware_bytes[start_index:self.get_malware_len()] * mult)[0:length]
        else:
            start_index = random.randint(PE_HEADER_OFFSET, self.get_malware_len() - length)
            return self._malware_bytes[start_index:start_index + length]

    def _get_none_mapping(self):
        is_prev_none = False
        curr_start = 0
        start_end_mapping = []
        for index, byte in enumerate(self._byte_mapping):
            if byte is None and not is_prev_none:
                curr_start = index
            if byte is None:
                is_prev_none = True
            if byte is not None and is_prev_none:
                start_end_mapping.append((curr_start, index))
                is_prev_none = False

        return start_end_mapping

    def fill_empty_with_code(self):
        none_mapping = self._get_none_mapping()

        for start_index, end_index in none_mapping:
            self.place(self.generate_random_x86_code(end_index - start_index), start_index)

    def get_as_bytestream(self):
        return bytes(self._byte_mapping)

    def get_file_len(self):
        return len(self._byte_mapping)

    def get_malware_len(self):
        return len(self._malware_bytes)
