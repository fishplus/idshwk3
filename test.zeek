global useragent:set[addr,string];
global num:table[addr] of count;
event http_header(c:connection,is_orig:bool,name:string,value:string)
	{
    if(name=="USER-AGENT")
      {
        add useragent[c$id$orig_h,value];
      }
	}
  event zeek_done()
  {
	local t1:addr;
	local t2:string;
	for ([t1,t2] in useragent)
	{
		if(t1 in num)
		{
			num[t1]+=1;
		}
		else
		{
			num[t1]=1;
		}
	}
    for(t1 in num)
    {
    	if(num[t1]>=3)
    	{
    		print fmt("%s is a proxy,where %s is the source IP",t1,t1);
    	}
    }
  }
