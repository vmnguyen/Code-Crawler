import os
import sys
import json
import re
import argparse
from colored import fg, attr


def print_banner():
	print('[!] Manual source code review helper')

def grep(filepath, signature):
    regex = ".*" + signature + ".*"
    regObj = re.compile(regex)
    res = []
    count = 0
    with open(filepath, encoding="utf8", errors='ignore') as f:
        for line in f:
            if regObj.match(line):
                res.append("{}" + str(count + 1) +"{}" + ": " + line.replace("{", "").replace("}", "").replace(signature, "{}" + signature + "{}", 1))
            count += 1
    return res

def find_files(path, regex):
    regObj = re.compile(regex)
    res = []
    for root, dirs, fnames in os.walk(path):
        for fname in fnames:
            ref_dir = os.path.relpath(root, path)
            if regObj.match(fname):			
                res.append(os.path.join(ref_dir, fname))
                #print(os.path.join(root, fname))
    return res

def do_find(signature):
	global path_to_code
	global files
	for file in files:
		if not (".svn" in file):
			res = grep(path_to_code + "/" +file, signature)
			if res != []:
				tmp = []
				for i in res:
					if ("import" not in i):
						tmp.append(i)
				if tmp != []:
					print("Found %s'%s'%s at %s%s%s"  %(fg("yellow"), signature, attr(0), fg("green"), file, attr(0)))
					for i in tmp:
						print(i.format(fg("red"), attr(0), fg("yellow"), attr(0)))
def convert_regrex(extension):
	res = ".*("
	for i in extension:
		res += i + "|"
	res = res[:-1] + ")"
	return res

def load_config():
	global path_to_config
	global files
	with open(path_to_config, "r") as config:
		data = json.load(config)
		language = "java"
		vuln = data['language'][language]['vulnerability']
		extension = data['language'][language]['extension']
		extension = convert_regrex(extension)
		#extension = r".*(java|jsp)"
		files = find_files(path_to_code,extension)
		for i in vuln:
			patterns = vuln[i]['pattern']
			for pattern in patterns:
				file = do_find(pattern)
				#if (file != []):
				#	print("[+] Found %s at:" % pattern)


def find_vuln():
	print("[!] Finding pattern in your code")
	config = load_config()

files = []
parser = argparse.ArgumentParser(description="Path to source code folder")
parser.add_argument('--path',help="Path to source code folder")
parser.add_argument("--config", help="Path to config file")
args = parser.parse_args()

path_to_code = args.path
print(path_to_code)
path_to_config = args.config
print(path_to_config)
print_banner()
find_vuln()
