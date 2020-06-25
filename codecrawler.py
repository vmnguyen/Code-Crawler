import os
import sys
import json
import re
import argparse
from colored import fg, attr

def print_banner():
	print('[!] Manual source code review helper')

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
                #res.append("{}" + str(count + 1) +"{}" + ": " + line.replace("{", "").replace("}", "").replace(signature, "{}" + signature + "{}", 1))
                detail.append({str(count + 1) : line})
                #print(detail)
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
            if reg_obj.match(fname) and (".svn" not in fname):	
                #print(fname)		
                res.append(os.path.join(ref_dir, fname))
                #print(os.path.join(root, fname))

    return res

def do_find(signature, path_to_code, files):
	result = {signature: []}
	for file in files:
		res = grep(path_to_code + "/" +file, signature)
		if res != {}:
			#print("Found %s'%s'%s at %s%s%s"  %(fg("yellow"), signature, attr(0), fg("green"), file, attr(0)))
			#print(match.format(fg("red"), attr(0), fg("yellow"), attr(0)))
			# {file : match.format(fg("red"), attr(0), fg("yellow"), attr(0))}
			result[signature].append(res)
	return result

def convert_regrex(extension):
	res = ".*\.("
	for i in extension:
		res += i + "|"
	res = res[:-1] + ")"

	return res

def find_vuln(path_to_code, path_to_config):
	#print("[!] Finding pattern in your code")
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

def main():
	parser = argparse.ArgumentParser(description="Path to source code folder")
	parser.add_argument('--path',help="Path to source code folder")
	parser.add_argument("--config", help="Path to config file")
	parser.add_argument("--output", help="Save result to file")
	parser.add_argument("--json", help="Save output as json file")
	args = parser.parse_args()
	path_to_code = args.path
	path_to_config = args.config
	path_to_output = args.output
	is_json_type = args.json
	#print_banner()

	result = find_vuln(path_to_code, path_to_config)
	print(json.dumps(result))
main()