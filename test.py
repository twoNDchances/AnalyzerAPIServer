import yara

def format_yara_rule(rule_input):
    # Xóa tất cả các dòng trống và thụt lề dư thừa
    lines = rule_input.strip().split("\n")
    
    # Loại bỏ thụt lề dư thừa và ghép các phần tử lại với nhau
    formatted_lines = []
    for line in lines:
        formatted_lines.append(line.strip())

    # Kết hợp các dòng lại thành một chuỗi YARA
    yara_rule = " ".join(formatted_lines)
    return yara_rule

rule_yara = '''rule php_dns  : webshell{
	meta:
		description = "Laudanum Injector Tools - file dns.php"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "01d5d16d876c55d77e094ce2b9c237de43b21a16"
	strings:
		$s1 = "$query = isset($_POST['query']) ? $_POST['query'] : '';" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "$result = dns_get_record($query, $types[$type], $authns, $addtl);" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "if ($_SERVER[\"REMOTE_ADDR\"] == $IP)" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "foreach (array_keys($types) as $t) {" fullword ascii
	condition:
		filesize < 15KB and all of them
}
'''

# print(format_yara_rule(rule_input=rule_yara))

rule = yara.compile(source='')

match = rule.match(data='Python')

print(match)