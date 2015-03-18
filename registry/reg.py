# -*- coding: utf-8 -*-
"""
Created on Mon Dec  9 15:23:01 2013

@author: slarinier
"""
from __future__ import unicode_literals
import re
import codecs
from utils import get_int_from_reversed_string, convert_windate, dosdate, get_csv_writer, write_list_to_csv
import registry_obj


def get_usb_key_info(key_name):
    """Extracts information from the registry concerning the USB key"""
    # HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\DeviceClasses\{a5dcbf10-6530-11d2-901f-00c04fb951ed}
    str_reg_key_usbinfo = r"SYSTEM\ControlSet001\Control\DeviceClasses\{a5dcbf10-6530-11d2-901f-00c04fb951ed}"

    # here is a sample of a key_name
    # ##?#USBSTOR#Disk&Ven_&Prod_USB_DISK_2.0&Rev_PMAP#07BC13025A3B03A1&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}
    # the logic is : there are 6 "#" so we should split this string on "#" and get the USB id (index 5)
    index_usb_id = 5
    usb_id = key_name.split("#")[index_usb_id]
    # now we want only the left part of the which may contain another separator "&" -> 07BC13025A3B03A1&0
    usb_id = usb_id.split("&")[0]

    # next we look in the registry for such an id
    key_ids = ""
    reg_key_info = registry_obj.get_registry_key(registry_obj.HKEY_LOCAL_MACHINE, str_reg_key_usbinfo)
    if reg_key_info:
        for i in xrange(reg_key_info.get_number_of_sub_keys()):
            subkey = reg_key_info.get_sub_key(i)
            if usb_id in subkey.get_name():
                # example of a key_info_name
                # ##?#USB#VID_26BD&PID_9917#0702313E309E0863#{a5dcbf10-6530-11d2-901f-00c04fb951ed}
                # the pattern is quite similar, a "#" separated string, with 5 as key id and 4 as VID&PID, we need
                # those 2
                index_usb_id = 4
                key_ids = subkey.get_name().split("#")[index_usb_id]
                break
    return key_ids


def csv_user_assist_value_decode_win7_and_after(str_value_datatmp, count_offset):
    """ The value in user assist has changed since Win7. It is taken into account here. """
    # 16 bytes data
    str_value_data_session = str_value_datatmp[0:4]
    str_value_data_session = unicode(get_int_from_reversed_string(str_value_data_session))
    str_value_data_count = str_value_datatmp[4:8]
    str_value_data_count = unicode(get_int_from_reversed_string(str_value_data_count) + count_offset + 1)
    str_value_data_focus = str_value_datatmp[12:16]
    str_value_data_focus = unicode(get_int_from_reversed_string(str_value_data_focus))
    str_value_data_timestamp = str_value_datatmp[60:68]
    try:
        timestamp = get_int_from_reversed_string(str_value_data_timestamp)
        date_last_exec = convert_windate(timestamp)
    except ValueError:
        date_last_exec = None
    arr_data = [str_value_data_session, str_value_data_count, str_value_data_focus]
    if date_last_exec:
        arr_data.append(date_last_exec)
    return arr_data


def csv_user_assist_value_decode_before_win7(str_value_datatmp, count_offset):
    # the Count registry contains values representing the programs
    # each value is separated as :
    # first 4 bytes are session
    # following 4 bytes are number of times the program has been run
    # next 8 bytes are the timestamp of last execution
    # each of those values are in big endian which have to be converted in little endian

    # 16 bytes data
    str_value_data_session = str_value_datatmp[0:4]
    str_value_data_session = unicode(get_int_from_reversed_string(str_value_data_session))
    str_value_data_count = str_value_datatmp[4:8]
    str_value_data_count = unicode(get_int_from_reversed_string(str_value_data_count) + count_offset + 1)
    str_value_data_timestamp = str_value_datatmp[8:16]
    try:
        timestamp = get_int_from_reversed_string(str_value_data_timestamp)
        date_last_exec = convert_windate(timestamp)
    except ValueError:
        date_last_exec = None
    arr_data = [str_value_data_session, str_value_data_count]
    if date_last_exec:
        arr_data.append(date_last_exec)
    return arr_data


def extract_filename_from_pidlmru(str_mru):
    l = []
    last_sep = 0
    # Split function, it will split only every 2 bytes
    for i in xrange(len(str_mru) / 2):
        if (2 * i) + 1 >= len(str_mru):
            break
        if str_mru[2 * i] == b"\x00" and str_mru[(2 * i) + 1] == b"\x00":
            l.append(str_mru[last_sep:2 * i])
            last_sep = 2 * (i + 1)
    l_printable = []
    for item in l:
        try:
            item_tmp = item.decode("utf-16")
            if re.match(".+\..+", item_tmp):
                l_printable.append(item_tmp)
        except UnicodeDecodeError:
            pass
    return l_printable


def decode_itempos(itempos):
    tmp_data = itempos
    # itempos size
    itempos_size = get_int_from_reversed_string(tmp_data[0:2])
    tmp_data = tmp_data[2:]
    # padding
    tmp_data = tmp_data[2:]
    # filesize
    filesize = get_int_from_reversed_string(tmp_data[0:4])
    tmp_data = tmp_data[4:]
    # timestamp
    timestamp_modified_date = tmp_data[0:2]
    tmp_data = tmp_data[2:]
    timestamp_modified_time = tmp_data[0:2]
    tmp_data = tmp_data[2:]
    timestamp_modified = dosdate(timestamp_modified_date, timestamp_modified_time).strftime("%d/%m/%Y %H:%M:%S")
    # padding
    tmp_data = tmp_data[2:]
    # filename
    filename = ""
    for i in xrange(len(tmp_data)):
        if ord(tmp_data[i]) == 0:  # NULL byte
            filename = tmp_data[0:i + 1]
            tmp_data = tmp_data[i + 1:]
            break
    # padding, it seems the next data will be following bytes "EF BE"
    for i in xrange(len(tmp_data) - 1):
        if ord(tmp_data[i]) == 0xef and ord(tmp_data[i + 1]) == 0xbe:
            tmp_data = tmp_data[i + 2:]
            break
    # timestamp created
    timestamp_created_date = tmp_data[0:2]
    tmp_data = tmp_data[2:]
    timestamp_created_time = tmp_data[0:2]
    tmp_data = tmp_data[2:]
    timestamp_created = dosdate(timestamp_created_date, timestamp_created_time).strftime("%d/%m/%Y %H:%M:%S")
    # timestamp modified
    timestamp_access_date = tmp_data[0:2]
    tmp_data = tmp_data[2:]
    timestamp_access_time = tmp_data[0:2]
    tmp_data = tmp_data[2:]
    timestamp_access = dosdate(timestamp_access_date, timestamp_access_time).strftime("%d/%m/%Y %H:%M:%S")

    tmp_arr = tmp_data.split(15 * b"\x00")
    if len(tmp_arr) >= 2:
        tmp_data = tmp_arr[1]
    else:
        tmp_data = ""
    # unicode string
    uni_filename = ""
    for i in xrange(len(tmp_data) / 2):
        if (2 * i) + 1 >= len(tmp_data):
            break
        if tmp_data[2 * i] == b"\x00" and tmp_data[(2 * i) + 1] == b"\x00":
            uni_filename = tmp_data[:2 * (i + 1)].decode("utf-16")
            break
    return [unicode(itempos_size), unicode(filesize), timestamp_modified, filename, timestamp_created,
            timestamp_access, uni_filename]


def construct_itempos_list(data):
    invalid_shitem_len = 0x14
    list_itempos = []
    tmp_data = data
    while True:
        try:
            if tmp_data[0:2] == b"\x14\x00":  # invalid SHITEM entry
                tmp_data = tmp_data[invalid_shitem_len + 8:]  # padding
                continue
            itempos_size = get_int_from_reversed_string(tmp_data[0:2])
            if itempos_size == 0:
                break
            list_itempos.append(tmp_data[:itempos_size])
            tmp_data = tmp_data[itempos_size:]
            # padding
            tmp_data = tmp_data[8:]
        except IndexError:
            break
    return list_itempos


def decode_shellbag_itempos_data(value_name, data):
    if "ItemPos" in value_name:
        header_len = 0x10
        unknown_padding_len = 0x8
        tmp_data = data[header_len + unknown_padding_len:]
        list_itempos = construct_itempos_list(tmp_data)
        list_itempos_printable = []
        for itempos in list_itempos:
            list_itempos_printable.append(decode_itempos(itempos))
        return list_itempos_printable


def append_reg_values(hive_list, key):
    for i in xrange(key.get_number_of_values()):
        value = key.get_value(i)
        hive_list.append(("VALUE", value.get_name(), value.get_data(), value.get_type(), key.get_last_written_time(),
                          value.get_path()))


def decode_recent_docs_mru(value):
    """Decodes recent docs MRU list
    Returns an array with 1st element being the filename, the second element being the symbolic link name"""
    value_decoded = []
    if b"\x00\x00\x00" in value:
        index = value.find(b"\x00\x00\x00")
        try:
            decoded = value[0:index + 1].decode("utf-16-le")
        except UnicodeDecodeError:
            try:
                decoded = value[0:index + 1].decode("utf-8")
            except UnicodeDecodeError:
                decoded = "".join([c for c in value[0:index + 1]])

        value_decoded.append(decoded)
        # index+3 because the last char also ends with \x00 + null bytes \x00\x00, +14 is the offset for the link name
        index_end_link_name = value.find(b"\x00", index + 3 + 14)
        value_decoded.append(value[index + 3 + 14:index_end_link_name])
    return value_decoded


def construct_list_from_key(hive_list, key, is_recursive=True):
    """Constructs the hive list. Recursive method if is_recursive=True.
    Keyword arguments:
    hive_list -- (List) the list to append to
    key -- (RegistryKey) the key to dump in the list
    """
    hive_list.append(("KEY", key.get_path(), key.get_last_written_time()))
    append_reg_values(hive_list, key)
    for i in xrange(key.get_number_of_sub_keys()):
        sub_key = key.get_sub_key(i)
        if sub_key and is_recursive:
            construct_list_from_key(hive_list, sub_key, is_recursive)


class _Reg(object):
    KEY_VALUE_STR = 0
    VALUE_NAME = 1
    VALUE_DATA = 2
    VALUE_TYPE = 3
    VALUE_LAST_WRITE_TIME = 4
    VALUE_PATH = 5

    KEY_PATH = 1
    KEY_LAST_WRITE_TIME = 2

    def __init__(self, params):
        if params["output_dir"] and params["computer_name"]:
            self.computer_name = params["computer_name"]
            self.output_dir = params["output_dir"]
        self.logger = params["logger"]
        # get logged off users" hives
        self.user_hives = []
        users = registry_obj.get_registry_key(registry_obj.HKEY_LOCAL_MACHINE,
                                              r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList")
        if users:
            for i in xrange(users.get_number_of_sub_keys()):
                user = users.get_sub_key(i)
                path = user.get_value_by_name("ProfileImagePath").get_data() + r"\NTUSER.DAT"
                try:
                    regf_file = registry_obj.RegfFile()
                    regf_file.open(path)
                    self.user_hives.append((user.get_name(), regf_file.get_root_key()))
                except IOError:  # user is logged on or not a user
                    pass

    def _generate_hklm_csv_list(self, to_csv_list, path, is_recursive=True):
        hive_list = self._get_list_from_registry_key(registry_obj.HKEY_LOCAL_MACHINE, path, is_recursive=is_recursive)
        for item in hive_list:
            if item[self.KEY_VALUE_STR] == "VALUE":
                to_csv_list.append((self.computer_name, item[self.VALUE_LAST_WRITE_TIME], "HKEY_LOCAL_MACHINE",
                                    item[self.VALUE_PATH], item[self.VALUE_NAME], item[self.KEY_VALUE_STR],
                                    registry_obj.get_str_type(item[self.VALUE_TYPE]), item[self.VALUE_DATA]))

    def _generate_hku_csv_list(self, to_csv_list, path, is_recursive=True):
        hive_list = self._get_list_from_registry_key(registry_obj.HKEY_USERS, path, is_recursive=is_recursive)
        for item in hive_list:
            if item[self.KEY_VALUE_STR] == "VALUE":
                to_csv_list.append((self.computer_name, item[self.VALUE_LAST_WRITE_TIME], "HKEY_USERS",
                                    item[self.VALUE_PATH], item[self.VALUE_NAME], item[self.KEY_VALUE_STR],
                                    registry_obj.get_str_type(item[self.VALUE_TYPE]), item[self.VALUE_DATA]))

    def _get_list_from_users_registry_key(self, key_path, is_recursive=True):
        hive_list = []
        key_users = registry_obj.get_registry_key(registry_obj.HKEY_USERS)
        if key_users:
            for i in xrange(key_users.get_number_of_sub_keys()):
                key_user = key_users.get_sub_key(i)
                key_data = key_user.get_sub_key_by_path(key_path)
                if key_data:
                    construct_list_from_key(hive_list, key_data, is_recursive)
        # same thing for logged off users (NTUSER.DAT)
        for sid, root_key in self.user_hives:
            key_data = root_key.get_sub_key_by_path(key_path)
            if key_data:
                key_data.prepend_path_with_sid(sid)
                construct_list_from_key(hive_list, key_data, is_recursive)
        return hive_list

    def _get_list_from_registry_key(self, hive, key_path, is_recursive=True):
        """Creates a list of all nodes and values from a registry key path.
        Keyword arguments:
        hive -- (String) the hive name
        key_path -- (String) the path of the key from which the list should be created
        """
        if hive == registry_obj.HKEY_USERS:
            return self._get_list_from_users_registry_key(key_path, is_recursive)
        hive_list = []
        root_key = registry_obj.get_registry_key(hive, key_path)
        if root_key:
            append_reg_values(hive_list, root_key)
            for i in xrange(root_key.get_number_of_sub_keys()):
                sub_key = root_key.get_sub_key(i)
                construct_list_from_key(hive_list, sub_key, is_recursive)
        return hive_list

    def _csv_user_assist(self, count_offset, is_win7_or_further):
        """Extracts information from UserAssist registry key which contains information about executed programs
        The count offset is for Windows versions before 7, where it would start at 6...
        """
        self.logger.info("Extracting user assist")
        path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\\UserAssist"
        count = "\Count"
        # logged on users
        users = registry_obj.RegistryKey(registry_obj.HKEY_USERS)
        hive_list = []
        for i in xrange(users.get_number_of_sub_keys()):
            user = users.get_sub_key(i)
            user_assist_key = user.get_sub_key_by_path(path)
            if user_assist_key:
                for j in xrange(user_assist_key.get_number_of_sub_keys()):
                    # getting Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count
                    path_no_sid = "\\".join(user_assist_key.get_sub_key(j).get_path().split("\\")[1:])
                    hive_list += self._get_list_from_registry_key(registry_obj.HKEY_USERS, path_no_sid + count)
        to_csv_list = []
        for item in hive_list:
            if item[self.KEY_VALUE_STR] == "VALUE":
                str_value_name = codecs.decode(item[self.VALUE_NAME], "rot_13")
                str_value_datatmp = item[self.VALUE_DATA]
                # some data are less than 16 bytes for some reason...
                if len(str_value_datatmp) < 16:
                    to_csv_list.append((self.computer_name, item[self.VALUE_LAST_WRITE_TIME], "HKEY_USERS",
                                        item[self.VALUE_PATH], item[self.VALUE_NAME], item[self.KEY_VALUE_STR],
                                        registry_obj.get_str_type(item[self.VALUE_TYPE]), str_value_name))
                else:
                    if is_win7_or_further:
                        data = csv_user_assist_value_decode_win7_and_after(str_value_datatmp, count_offset)
                    else:
                        data = csv_user_assist_value_decode_before_win7(str_value_datatmp, count_offset)
                    to_csv_list.append((self.computer_name, item[self.VALUE_LAST_WRITE_TIME], "HKEY_USERS",
                                        item[self.VALUE_PATH], item[self.VALUE_NAME], item[self.KEY_VALUE_STR],
                                        registry_obj.get_str_type(item[self.VALUE_TYPE]), str_value_name) + tuple(data))
        with open(self.output_dir + "\\" + self.computer_name + "_user_assist.csv", "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(to_csv_list, csv_writer)

    def _csv_open_save_mru(self, str_opensave_mru):
        """Extracts OpenSaveMRU containing information about opened and saved windows"""
        # TODO : Win XP
        self.logger.info("Extracting open save MRU")
        hive_list = self._get_list_from_registry_key(registry_obj.HKEY_USERS, str_opensave_mru)
        to_csv_list = []
        for item in hive_list:
            if item[self.VALUE_NAME] != "MRUListEx":
                l_printable = extract_filename_from_pidlmru(item[self.VALUE_DATA])
                # FIXME: (dirty) if the list is empty it's probably because the string is off by 1...
                if len(l_printable) == 0:
                    # So we take away the first char to have a correct offset (modulo 2)
                    l_printable = extract_filename_from_pidlmru(item[self.VALUE_DATA][1:])
                if len(l_printable) != 0:
                    str_printable = l_printable[-1]
                    if item[self.KEY_VALUE_STR] == "VALUE":
                        to_csv_list.append((self.computer_name, item[self.VALUE_LAST_WRITE_TIME], "HKEY_USERS",
                                            item[self.VALUE_PATH], item[self.VALUE_NAME], item[self.KEY_VALUE_STR],
                                            registry_obj.get_str_type(item[self.VALUE_TYPE]), str_printable))
                else:  # if the length is still 0 then don't know
                    if item[self.KEY_VALUE_STR] == "VALUE":
                        to_csv_list.append((self.computer_name, item[self.VALUE_LAST_WRITE_TIME], "HKEY_USERS",
                                            item[self.VALUE_PATH], item[self.VALUE_NAME], item[self.KEY_VALUE_STR],
                                            registry_obj.get_str_type(item[self.VALUE_TYPE]), item[self.VALUE_DATA]))
        with open(self.output_dir + "\\" + self.computer_name + "_opensaveMRU.csv", "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(to_csv_list, csv_writer)

    def csv_registry_services(self):
        """Extracts services"""
        self.logger.info("Extracting services")
        path = r"System\CurrentControlSet\Services"
        to_csv_list = []
        self._generate_hklm_csv_list(to_csv_list, path)
        with open(self.output_dir + "\\" + self.computer_name + "_registry_services.csv", "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(to_csv_list, csv_writer)

    def csv_recent_docs(self):
        """Extracts information about recently opened files saved location and opened date"""
        self.logger.info("Extracting recent docs")
        path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
        hive_list = self._get_list_from_registry_key(registry_obj.HKEY_USERS, path)
        to_csv_list = []
        for item in hive_list:
            if item[self.KEY_VALUE_STR] == "VALUE":
                if item[self.VALUE_NAME] != "MRUListEx":
                    value_decoded = decode_recent_docs_mru(item[self.VALUE_DATA])
                    to_csv_list.append((self.computer_name, item[self.VALUE_LAST_WRITE_TIME], "HKEY_USERS",
                                        item[self.VALUE_PATH], item[self.VALUE_NAME], item[self.KEY_VALUE_STR],
                                        registry_obj.get_str_type(item[self.VALUE_TYPE])) + tuple(value_decoded))
        with open(self.output_dir + "\\" + self.computer_name + "_recent_docs.csv", "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(to_csv_list, csv_writer)

    def csv_installer_folder(self):
        """Extracts information about folders which are created at installation"""
        self.logger.info("Extracting installer folders")
        path = r"Software\Microsoft\Windows\CurrentVersion\Installer\Folders"
        to_csv_list = []
        self._generate_hklm_csv_list(to_csv_list, path)
        with open(self.output_dir + "\\" + self.computer_name + "_installer_folder.csv", "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(to_csv_list, csv_writer)

    def csv_shell_bags(self):
        """Extracts shellbags: size, view, icon and position for Explorer folders"""
        # TODO Check Vista and under
        self.logger.info("Extracting shell bags")
        paths = [r"Software\Microsoft\Windows\Shell\Bags",
                 r"Software\Microsoft\Windows\Shell\BagMRU",
                 r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags",
                 r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU"]
        hive_list = []
        for path in paths:
            hive_list += self._get_list_from_registry_key(registry_obj.HKEY_USERS, path)
        to_csv_list = []
        for item in hive_list:
            try:
                datas = decode_shellbag_itempos_data(item[self.VALUE_NAME], item[self.VALUE_DATA])
            except IndexError:
                self.logger.error("Error in shellbag data format for " + item[self.VALUE_NAME])
                datas = None
            if datas:
                for data in datas:
                    if item[self.KEY_VALUE_STR] == "VALUE":
                        to_csv_list.append((self.computer_name, item[self.VALUE_LAST_WRITE_TIME], "HKEY_USERS",
                                            item[self.VALUE_PATH], item[self.VALUE_NAME], item[self.KEY_VALUE_STR],
                                            registry_obj.get_str_type(item[self.VALUE_TYPE])) + tuple(data))
            else:
                if item[self.KEY_VALUE_STR] == "VALUE":
                    to_csv_list.append((self.computer_name, item[self.VALUE_LAST_WRITE_TIME], "HKEY_USERS",
                                        item[self.VALUE_PATH], item[self.VALUE_NAME], item[self.KEY_VALUE_STR],
                                        registry_obj.get_str_type(item[self.VALUE_TYPE]), item[self.VALUE_DATA]))

        with open(self.output_dir + "\\" + self.computer_name + "_shellbags.csv", "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(to_csv_list, csv_writer)

    def csv_startup_programs(self):
        """Extracts programs running at startup"""
        self.logger.info("Extracting startup programs")
        software = "Software"
        wow = r"\Wow6432Node"
        ts_run = (r"\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software"
                  r"\Microsoft\Windows\CurrentVersion\Run")
        ts_run_once = (r"\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software"
                       r"\Microsoft\Windows\CurrentVersion\RunOnce")
        paths = [r"\Microsoft\Windows\CurrentVersion\Run",
                 r"\Microsoft\Windows\CurrentVersion\RunOnce",
                 r"\Microsoft\Windows\CurrentVersion\RunOnceEx",
                 r"\Microsoft\Windows\CurrentVersion\RunServices",
                 r"\Microsoft\Windows\CurrentVersion\RunServicesOnce",
                 r"\Microsoft\Windows NT\CurrentVersion\Winlogon\\Userinit",
                 r"\Microsoft\Windows NT\CurrentVersion\Windows",
                 r"\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                 ts_run,
                 ts_run_once]
        to_csv_list = []
        for path in paths:
            full_path = software + path
            self._generate_hklm_csv_list(to_csv_list, full_path)
            full_path = software + wow + path
            self._generate_hklm_csv_list(to_csv_list, full_path)

        paths = [r"\Microsoft\Windows\CurrentVersion\Run",
                 r"\Microsoft\Windows\CurrentVersion\RunOnce",
                 r"\Microsoft\Windows\CurrentVersion\RunOnceEx",
                 r"\Microsoft\Windows\CurrentVersion\RunServices",
                 r"\Microsoft\Windows\CurrentVersion\RunServicesOnce",
                 r"\Microsoft\Windows NT\CurrentVersion\Windows",
                 r"\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                 ts_run,
                 ts_run_once]
        for path in paths:
            full_path = software + path
            self._generate_hku_csv_list(to_csv_list, full_path)
            full_path = software + wow + path
            self._generate_hku_csv_list(to_csv_list, full_path)
        with open(self.output_dir + "\\" + self.computer_name + "_startup.csv", "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(to_csv_list, csv_writer)

    def csv_installed_components(self):
        """Extracts installed components"""
        self.logger.info("Extracting installed components")
        path = r"Software\Microsoft\Active Setup\Installed Components"
        to_csv_list = []
        self._generate_hklm_csv_list(to_csv_list, path)
        with open(self.output_dir + "\\" + self.computer_name + "_installed_components.csv", "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(to_csv_list, csv_writer)

    def csv_winlogon_values(self):
        """Extracts winlogon values"""
        self.logger.info("Extracting winlogon values")
        path = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
        to_csv_list = []
        self._generate_hklm_csv_list(to_csv_list, path)
        self._generate_hku_csv_list(to_csv_list, path)
        with open(self.output_dir + "\\" + self.computer_name + "_winlogon_values.csv", "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(to_csv_list, csv_writer)

    def csv_windows_values(self):
        """Extracts windows values"""
        self.logger.info("Extracting windows values")
        path = r"Software\Microsoft\Windows NT\CurrentVersion\Windows"
        to_csv_list = []
        self._generate_hklm_csv_list(to_csv_list, path)
        self._generate_hku_csv_list(to_csv_list, path)
        with open(self.output_dir + "\\" + self.computer_name + "_windows_values.csv", "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(to_csv_list, csv_writer)

    def csv_usb_history(self):
        """Extracts information about USB devices"""
        self.logger.info("Extracting USB history")
        hive_list = self._get_list_from_registry_key(
            registry_obj.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\DeviceClasses\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",
            is_recursive=False)
        to_csv_list = []
        for item in hive_list:
            if item[self.KEY_VALUE_STR] == "KEY":
                usb_decoded = get_usb_key_info(item[self.KEY_PATH])
                to_csv_list.append((self.computer_name, item[self.KEY_LAST_WRITE_TIME], "HKEY_LOCAL_MACHINE",
                                    item[self.KEY_PATH], item[self.KEY_VALUE_STR], usb_decoded))
        with open(self.output_dir + "\\" + self.computer_name + "_USBHistory.csv", "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(to_csv_list, csv_writer)

    def csv_run_mru_start(self):
        """Extracts run MRU, containing the 26 last oommands executed using the RUN command"""
        self.logger.info("Extracting Run MRU")
        path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        to_csv_list = []
        self._generate_hku_csv_list(to_csv_list, path)
        with open(self.output_dir + "\\" + self.computer_name + "_run_MRU_start.csv", "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(to_csv_list, csv_writer)