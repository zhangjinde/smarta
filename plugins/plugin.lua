-- lua plugin utilities
-- author: ery.lee@gmail.com from monit.cn

require("alt_getopt")

-- basic functions
function eval(str) 
  fun = assert(loadstring(str))
  return fun()
end

-- extend table functions
table.filter = function(array, func)
  local new_array = {}
  for _,v in ipairs(array) do
    if func(v) then
      table.insert(new_array, v)
    end
  end
  return new_array
end

table.map = function(array, func)
  local new_array = {}
  for i,v in ipairs(array) do
  new_array[i] = func(v)
  end
  return new_array
end

table.map2 = function(array, func)
  local new_array = {}
  for k,v in pairs(array) do
    table.insert(new_array, func(k, v))
  end
  return new_array
end

table.zip = function(array1, array2)
  if not (#array1 == #array2) then 
    error("cannot zip arrays with different length") 
  end
  local new_array = {}
  for i,v in ipairs(array1) do
    new_array[array1[i]] = array2[i]
  end
  return new_array
end

-- extend string functions
string.trim = function(s)
  return s:match"^%s*(.-)%s*$"
end

string.join = function(tab, delimiter)
  return table.concat(tab, delimiter)
end

string.split = function(str, pat)
  local t = {}  -- NOTE: use {n = 0} in Lua-5.0
  local fpat = "(.-)" .. pat
  local last_end = 1
  local s, e, cap = str:find(fpat, 1)
  while s do
    if s ~= 1 or cap ~= "" then
    table.insert(t,cap)
    end
    last_end = e+1
    s, e, cap = str:find(fpat, last_end)
  end
  if last_end <= #str then
    cap = str:sub(last_end)
    table.insert(t, cap)
  end
  return t
end

-- extend os functions
os.cmd = function(cmd) 
  local tmp = os.tmpname()
  os.execute(cmd.." > "..tmp.." 2>&1")
  local f = assert(io.open(tmp, "r"))
  local output = f:read("*all")
  f:close()
  os.remove(tmp)
  return output
end

os.uname = function() 
    return string.trim(os.cmd("uname"))
end

-- getopt, POSIX style command line argument parser
function getopts(arg, opts, long_opts )
    return alt_getopt.get_opts(arg, opts, long_opts)
end
