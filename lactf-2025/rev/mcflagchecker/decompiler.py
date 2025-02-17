import os

ignored_commands = ["gamerule", "fill", "kill", "forceload", "give", "say"]

def get_varname(player, objective):
    if player == "Global":
        return f"{player}['{objective}']"
    elif objective == "Constant":
        return f"{objective}['{player}']"
    else:
        raise ValueError(f"Unknown player: {player}")

def parse_condition(tokens): # Example: 'if', 'score', 'Global', 'var4', 'matches', '1' -> 'var4 == 1'
    assert tokens[0] == "if" or tokens[0] == "unless"
    if tokens[1] == "score":
        # var_name = f"{tokens[3]}.{tokens[2]}" if tokens[2] != "Global" else tokens[3]
        var_name = get_varname(tokens[2], tokens[3])
        if tokens[4] == "matches":
            if tokens[5].isnumeric():
                return f"{var_name} {"==" if tokens[0] == "if" else "!="} {tokens[5]}"
            else:
                assert tokens[5].endswith("..")
                minimum = tokens[5][:-2]
                return f"{var_name} {">=" if tokens[0] == "if" else "<"} {minimum}"
        else:
            # other_var_name = f"{tokens[6]}.{tokens[5]}" if tokens[5] != "Global" else tokens[6]
            other_var_name = get_varname(tokens[5], tokens[6])
            return f"{"not " if tokens[0] == "unless" else ""}{var_name} {tokens[4]} {other_var_name}"
    else:
        raise ValueError(f"Unknown if command: {tokens[1]}")
        

def transpile_line(tokens, objectives):
    if tokens[0] == "scoreboard":
        if tokens[1] == "players":
            # var_name = f"{tokens[4]}.{tokens[3]}" if tokens[3] != "Global" else tokens[4]
            var_name = get_varname(tokens[3], tokens[4])
            if tokens[2] == "set":
                return f"{var_name} = {tokens[5]}"
            elif tokens[2] == "add":
                return f"{var_name} += {tokens[5]}"
            elif tokens[2] == "operation":
                return f"{var_name} {tokens[5]} {get_varname(tokens[6], tokens[7])}"
        elif tokens[1] == "objectives":
            if tokens[2] == "add":
                objectives.append(tokens[3])
                return f"# Define {tokens[3]}"
            else:
                raise ValueError(f"Unknown scoreboard command: {tokens[2]}")
        else:
            raise ValueError(f"Unknown scoreboard command: {tokens[1]}")
    elif tokens[0] in ignored_commands:
        return f"print({tokens})"   
    elif tokens[0] == "function":
        assert len(tokens) == 2
        return f"{tokens[1].replace("chall:", "").replace('/', '_')}()"
    elif tokens[0] == "execute":
        if tokens[1] == "if" or tokens[1] == "unless":
            i = 1
            conditions = []
            while True:
                if tokens[i] == "run":
                    return f"if {' and '.join(conditions)}: {transpile_line(tokens[i+1:], objectives)}"
                conditions.append(parse_condition(tokens[i:]))
                i += 6 if tokens[i+4] == "matches" else 7
        elif tokens[1] == "store":
            assert tokens[13] == "RecordItem.tag.Storage"
            # var_name = f"{tokens[5]}.{tokens[4]}" if tokens[4] != "Global" else tokens[5]
            var_name = get_varname(tokens[4], tokens[5])
            location = f"{tokens[10]}_{tokens[11]}_{tokens[12]}"
            return f"{var_name} = Storage['{location}']"
        else:
            print(tokens)
            raise ValueError(f"Unknown execute command: {tokens[1]}")
    elif tokens[0] == "data":
        if tokens[1] == "modify":
            return '#' + (' '.join(tokens))
        else:
            assert tokens[1] == "merge" and tokens[2] == "block"
            location = f"{tokens[3]}_{tokens[4]}_{tokens[5]}"
            data = tokens[7].rstrip('}')
            return f"Storage['{location}'] = {data}"
    else:
        print(tokens)
        raise ValueError(f"Unknown command: {tokens[0]}")
    
    print(tokens)
    raise ValueError(f"No return")

datapack_root = "data"
transpiled_root = "transpiled"
def transpile_file(file, objectives):
    if file.endswith(".json"):
        return

    with open(os.path.join(datapack_root, file)) as f:
        lines = f.readlines()
    
    transpiled_lines = []
    for line in lines:
        transpiled_line = transpile_line(line.strip().split(), objectives)
        if not transpiled_line[0] == "#":
            transpiled_lines.append(transpiled_line)

    out_path = os.path.join(transpiled_root, file)
    out_path_dir = os.path.dirname(out_path)
    if not os.path.exists(out_path_dir):
        os.makedirs(out_path_dir)
    
    with open(out_path, "w") as f:
        f.write("\n".join([line if line is not None else "None" for line in transpiled_lines]))

def transpile_all():
    objectives = []
    for root, _, files in os.walk(datapack_root):
        for file in files:
            transpile_file(os.path.relpath(os.path.join(root, file), datapack_root), objectives)

    return objectives

def link_all(output, objectives):
    functions = {}
    for root, _, files in os.walk(os.path.join(transpiled_root, "chall", "functions")):
        for file in files:
            parent = root.replace(os.path.join(transpiled_root, "chall", "functions"), "").replace("/", "_").lstrip('_')
            function_name = (parent + "_" if len(parent) > 0 else "") + file.replace(".mcfunction", "")
            with open(os.path.join(root, file)) as f:
                functions[function_name] = f.readlines()

    with open(output, "w") as f:
        # for objective in objectives:
        #     f.write(f"{objective} = {{}}\n")
        # f.write("\n")
        f.write("Constant = {}\n")
        f.write("Global = {}\n")
        f.write("Storage = {}\n")
        f.write("\n")

        for function_name, lines in functions.items():
            f.write(f"# {function_name}\n")
            f.write(f"def {function_name}():\n")
            for line in lines:
                f.write(f"    {line.strip('\n')}\n")
            f.write("\n")

        f.write('reset()\n')
        f.write('check_flag()\n')

if __name__ == "__main__":
    objectives = transpile_all()
    link_all("decompiled.py", objectives)
