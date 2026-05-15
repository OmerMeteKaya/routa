init = function(args)
   local r = {}
   r[1] = wrk.format(nil, "/")
   -- Aynı bağlantı üzerinden arka arkaya 16 istek paketle (Pipelining)
   req = table.concat({
      r[1], r[1], r[1], r[1], r[1], r[1], r[1], r[1],
      r[1], r[1], r[1], r[1], r[1], r[1], r[1], r[1]
   })
end

request = function()
   return req
end
