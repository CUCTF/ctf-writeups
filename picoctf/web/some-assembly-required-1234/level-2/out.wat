(module
  (type (;0;) (func))
  (type (;1;) (func (param i32 i32) (result i32)))
  (type (;2;) (func (result i32)))
  (type (;3;) (func (param i32 i32)))
  (func (;0;) (type 0))
  (func (;1;) (type 1) (param i32 i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get 0
    local.set 2
    i32.const 32
    local.set 3
    local.get 2
    local.get 3
    i32.sub
    local.set 4
    local.get 4
    local.get 0
    i32.store offset=24
    local.get 4
    local.get 1
    i32.store offset=20
    local.get 4
    i32.load offset=24
    local.set 5
    local.get 4
    local.get 5
    i32.store offset=16
    local.get 4
    i32.load offset=20
    local.set 6
    local.get 4
    local.get 6
    i32.store offset=12
    block  ;; label = @1
      loop  ;; label = @2
        local.get 4
        i32.load offset=16
        local.set 7
        i32.const 1
        local.set 8
        local.get 7
        local.get 8
        i32.add
        local.set 9
        local.get 4
        local.get 9
        i32.store offset=16
        local.get 7
        i32.load8_u
        local.set 10
        local.get 4
        local.get 10
        i32.store8 offset=11
        local.get 4
        i32.load offset=12
        local.set 11
        i32.const 1
        local.set 12
        local.get 11
        local.get 12
        i32.add
        local.set 13
        local.get 4
        local.get 13
        i32.store offset=12
        local.get 11
        i32.load8_u
        local.set 14
        local.get 4
        local.get 14
        i32.store8 offset=10
        local.get 4
        i32.load8_u offset=11
        local.set 15
        i32.const 255
        local.set 16
        local.get 15
        local.get 16
        i32.and
        local.set 17
        block  ;; label = @3
          local.get 17
          br_if 0 (;@3;)
          local.get 4
          i32.load8_u offset=11
          local.set 18
          i32.const 255
          local.set 19
          local.get 18
          local.get 19
          i32.and
          local.set 20
          local.get 4
          i32.load8_u offset=10
          local.set 21
          i32.const 255
          local.set 22
          local.get 21
          local.get 22
          i32.and
          local.set 23
          local.get 20
          local.get 23
          i32.sub
          local.set 24
          local.get 4
          local.get 24
          i32.store offset=28
          br 2 (;@1;)
        end
        local.get 4
        i32.load8_u offset=11
        local.set 25
        i32.const 255
        local.set 26
        local.get 25
        local.get 26
        i32.and
        local.set 27
        local.get 4
        i32.load8_u offset=10
        local.set 28
        i32.const 255
        local.set 29
        local.get 28
        local.get 29
        i32.and
        local.set 30
        local.get 27
        local.set 31
        local.get 30
        local.set 32
        local.get 31
        local.get 32
        i32.eq
        local.set 33
        i32.const 1
        local.set 34
        local.get 33
        local.get 34
        i32.and
        local.set 35
        local.get 35
        br_if 0 (;@2;)
      end
      local.get 4
      i32.load8_u offset=11
      local.set 36
      i32.const 255
      local.set 37
      local.get 36
      local.get 37
      i32.and
      local.set 38
      local.get 4
      i32.load8_u offset=10
      local.set 39
      i32.const 255
      local.set 40
      local.get 39
      local.get 40
      i32.and
      local.set 41
      local.get 38
      local.get 41
      i32.sub
      local.set 42
      local.get 4
      local.get 42
      i32.store offset=28
    end
    local.get 4
    i32.load offset=28
    local.set 43
    local.get 43
    return)
  (func (;2;) (type 2) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    i32.const 0
    local.set 0
    i32.const 1072
    local.set 1
    i32.const 1024
    local.set 2
    local.get 2
    local.get 1
    call 1
    local.set 3
    local.get 3
    local.set 4
    local.get 0
    local.set 5
    local.get 4
    local.get 5
    i32.ne
    local.set 6
    i32.const -1
    local.set 7
    local.get 6
    local.get 7
    i32.xor
    local.set 8
    i32.const 1
    local.set 9
    local.get 8
    local.get 9
    i32.and
    local.set 10
    local.get 10
    return)
  (func (;3;) (type 3) (param i32 i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get 0
    local.set 2
    i32.const 16
    local.set 3
    local.get 2
    local.get 3
    i32.sub
    local.set 4
    local.get 4
    local.get 0
    i32.store offset=12
    local.get 4
    local.get 1
    i32.store offset=8
    local.get 4
    i32.load offset=12
    local.set 5
    block  ;; label = @1
      local.get 5
      i32.eqz
      br_if 0 (;@1;)
      local.get 4
      i32.load offset=12
      local.set 6
      i32.const 8
      local.set 7
      local.get 6
      local.get 7
      i32.xor
      local.set 8
      local.get 4
      local.get 8
      i32.store offset=12
    end
    local.get 4
    i32.load offset=12
    local.set 9
    local.get 4
    i32.load offset=8
    local.set 10
    local.get 10
    local.get 9
    i32.store8 offset=1072
    return)
  (table (;0;) 1 1 funcref)
  (memory (;0;) 2)
  (global (;0;) (mut i32) (i32.const 66864))
  (global (;1;) i32 (i32.const 1072))
  (global (;2;) i32 (i32.const 1024))
  (global (;3;) i32 (i32.const 1328))
  (global (;4;) i32 (i32.const 1024))
  (global (;5;) i32 (i32.const 66864))
  (global (;6;) i32 (i32.const 0))
  (global (;7;) i32 (i32.const 1))
  (export "memory" (memory 0))
  (export "__wasm_call_ctors" (func 0))
  (export "strcmp" (func 1))
  (export "check_flag" (func 2))
  (export "input" (global 1))
  (export "copy_char" (func 3))
  (export "__dso_handle" (global 2))
  (export "__data_end" (global 3))
  (export "__global_base" (global 4))
  (export "__heap_base" (global 5))
  (export "__memory_base" (global 6))
  (export "__table_base" (global 7))
  (data (;0;) (i32.const 1024) "xakgK\5cNs((j:l9<mimk?:k;9;8=8?=0?>jnn:j=lu\00\00"))
