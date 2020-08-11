import os
import sys
import json
import re
import argparse
from colored import fg, attr

def print_banner():
	print('''   ___         _        ___                 _         
  / __|___  __| |___   / __|_ _ __ ___ __ _| |___ _ _ 
 | (__/ _ \/ _` / -_) | (__| '_/ _` \ V  V / / -_) '_|
  \___\___/\__,_\___|  \___|_| \__,_|\_/\_/|_\___|_|by %s''' % "vmnguyen")

def additional_condition(line):
	#Add more condition here
	if ("import " in line):
		return False
	return True

def grep(filepath, signature):
    regex = ".*" + signature + ".*"
    reg_obj = re.compile(regex)
    restmp = {}
    detail = []
    count = 0
    with open(filepath, encoding="utf8", errors='ignore') as f:
        for line in f:
            if reg_obj.match(line) and additional_condition(line):
                detail.append({str(count + 1) : line})
            count += 1
        if (detail != []):
            restmp = {filepath : detail}

    return restmp

def find_files(path, regex):
    reg_obj = re.compile(regex)
    res = []

    for root, dirs, fnames in os.walk(path):
        for fname in fnames:
            ref_dir = os.path.relpath(root, path)
            if reg_obj.match(fname):	
                res.append(os.path.join(ref_dir, fname))

    return res

def format_with_color(line_number, line, signature):
	text = "{}" + str(int(line_number) + 1) +"{}" + ":\t" + line.replace("{", "").replace("}", "").replace(signature, "{}" + signature + "{}", 1)
                
	print(text.format(fg("red"), attr(0), fg("yellow"), attr(0)))

def do_find(signature, path_to_code, files):
	result = {signature: []}
	for file in files:
		res = grep(path_to_code + "/" +file, signature)
		if res != {}:
			print("Found %s'%s'%s at %s%s%s"  %(fg("yellow"), signature, attr(0), fg("green"), file, attr(0)))
			for i in res:
				for j in res[i]:
					for z in j:
						format_with_color(z, j[z], signature)
			result[signature].append(res)
	return result

def convert_regrex(extension):
	res = ".*\.("
	for i in extension:
		res += i + "|"
	res = res[:-1] + ")$"

	return res

def find_vuln(path_to_code, path_to_config):
	print("[!] Finding pattern in your code")
	result = {}
	with open(path_to_config, "r") as config:
		data = json.load(config)
		language = "java"
		vuln = data['language'][language]['vulnerability']
		extension = data['language'][language]['extension']
		extension = convert_regrex(extension)
		files = find_files(path_to_code,extension)

		for i in vuln:
			patterns = vuln[i]['pattern']
			tmp = {i : []}
			for pattern in patterns:
				found = do_find(pattern, path_to_code, files)
				if (found != {} ):
					tmp[i].append((found))
					result.update(tmp)
			#print(tmp)
	return result

def save_result(path_to_output, result):
	fileobject = open(path_to_output, "w")
	json.dump(result, fileobject)
	fileobject.close()

def print_exit():
	print("%s[!]%s Finished scan the source code." % (fg("green"), attr(0)))

def main():
	parser = argparse.ArgumentParser(description="Path to source code folder")
	parser.add_argument('--path',help="Path to source code folder")
	parser.add_argument("--config", help="Path to config file")
	parser.add_argument("--output", help="Save result to file")
	args = parser.parse_args()
	path_to_code = args.path
	path_to_config = args.config
	path_to_output = args.output

	print_banner()
	result = find_vuln(path_to_code, path_to_config)
	save_result(path_to_output, result)
	print_exit()
main()
