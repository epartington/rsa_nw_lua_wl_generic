local parserName = "lua_whitelist_generic"
-- this shows in the config screen
local parserVersion = "2019.01.15.2"

local generic = nw.createParser(parserName, parserName .. ": " .. parserVersion)
-- this shows in the mouseover

nw.logDebug(parserName .. " " .. parserVersion)

local summary = {["parserName"] = parserName, ["parserVersion"] = parserVersion}

summary.parserDetails = [=[
https://riptutorial.com/lua/example/20315/lua-pattern-matching
generic whitelisting of well known hostname endpoints

looks for hostname and domains in the following keys 
    alias.host
    host.src
    host.dst
    fqdn

then marks them in the following keys
filter
with whitelist meta
    whitelist               - for global whitelisting
    <name here>             - for description specifics

the parser attempts to match both exact AND subdomain matches so for an entry that has both
a specific domain and overlapping *. wildcard subdomain you will potentially get 6 values written (3 for each match)
this can be changed by ordering the list from specific to substring and putting a break in teh loop to prevent after first match (specific first)

]=]

summary.dependencies = {
    ["parsers"] = {
        "NETWORK",
        "FeedParser"
    },
}

summary.conflicts = {
    ["parsers"] = {
        ""
    }
}

summary.keyUsage = {
    ["filter"]  = "'whitelist','generic','<name>'",
    ["feed.name"]  = "lua_whitelist_generic",
    
}

summary.investigation = {
    ["filter"] = {
        ["whitelist"] = {
            ["filter"] = {
                "generic",
            },
            ["inv.category"] = {
                "",
            },
            ["feed.name"] = "lua_whitelist_generic",
            ["reason"] = ""
        },
    },
}

summary.liveTags = {
    "whitelist",
}

--[[
    VERSION
        2018.08.11.1  eric.partington@rsa.com  11.1.0.0-8987.3  UDM
        2018.10.10.2  eric.partington@rsa.com  updated to work with different lua import list
        

    OPTIONS

        none


    IMPLEMENTATION

        Relies on meta registered by other parsers.


    TODO

        none?

--]]

--local debugParser = require('debugParser')

local lookup_list = ({
["*.ipv6"] = {"whitelist","generic","reverse_dns"},
["*.ip6.arpa"] = {"whitelist","generic","reverse_dns"},
["*.in-addr.arpa"] = {"whitelist","generic","reverse_dns"},
["*.telemetry.mozilla.org"] = {"whitelist","generic","firefox"},
["*getpocket.cdn.mozilla.net"] = {"whitelist","generic","firefox"},
["*.services.mozilla.com"] = {"whitelist","generic","firefox"},
["*.gvt1.com"] = {"whitelist","generic","chrome"},
["*.gvt2.com"] = {"whitelist","generic","chrome"},
["normandy.cdn.mozilla.net"] = {"whitelist","generic","firefox"},
["shavar.prod.mozaws.net"] = {"whitelist","generic","firefox"},
["detectportal.firefox.com"] = {"whitelist","generic","firefox"},
["clients2.google.com"] = {"whitelist","generic","chrome"},
["content-signature.cdn.mozilla.net"] = {"whitelist","generic","firefox"},
["versioncheck-bg.addons.mozilla.org"] = {"whitelist","generic","firefox"},
["versioncheck.addons.mozilla.org"] = {"whitelist","generic","firefox"},
["blocklists-settings.prod.mozaws.net"] = {"whitelist","generic","firefox"},
["sqm.telemetry.microsoft.com"] = {"whitelist","generic","windows"},
["c.urs.microsoft.com"] = {"whitelist","generic","windows"},
["vortex-win.data.microsoft.com"] = {"whitelist","generic","windows"},
["sqm.telemetry.microsoft.com.nsatc.net"] = {"whitelist","generic","windows"},
["login.msa.akadns6.net"] = {"whitelist","generic","windows"},
["www.msftconnecttest.com"] = {"whitelist","generic","windows"},
["au.download.windowsupdate.com.edgesuite.net"] = {"whitelist","generic","windows"},
["iecvlist.microsoft.com"] = {"whitelist","generic","windows"},
["asimov-win.settings.data.microsoft.com.akadns.net"] = {"whitelist","generic","windows"},
["v10-win.vortex.data.microsoft.com.akadns.net"] = {"whitelist","generic","windows"},
["audownload.windowsupdate.nsatc.net"] = {"whitelist","generic","windows"},
["asimov-win.vortex.data.microsoft.com.akadns.net"] = {"whitelist","generic","windows"},
["vs.login.msa.akadns6.net"] = {"whitelist","generic","windows"},
["www.msftncsi.com"] = {"whitelist","generic","windows"}
})

--[[
sample code
local categories = {
   ["domain1"] = {
       "whitelist",
       "shopping",
       "ecomm"
   }
}

if categories[someDomain] then
   for i,j in ipairs(categories[someDomain]) do
       ... something ...
   end
end]]--

generic:setKeys({
	nwlanguagekey.create("filter", nwtypes.Text),
	nwlanguagekey.create("feed.name", nwtypes.Text),
})

function generic:onHost(idx, host)
    --lowercase the incoming value
    host = string.lower(host)
	
    for domain in pairs(lookup_list) do
   
        -- replace the * wildcard in the list with .*
        domain_esc = string.gsub(domain, "%*", "%.%*")
        --print("domain after gsub for * " .. domain)
         -- for hostnames that have a - in them we need to escape that with %% so the end string ends %- (first % escapes on replace)
        domain_esc = string.gsub(domain_esc, "%-", "%%-")
        -- for hostnames that have a . in them we need to escape that with %% so the end string ends %. (first % escapes on replace)
        domain_esc = string.gsub(domain_esc, "%.", "%%.")
        
        if string.match(host, "^"..domain_esc.."$") then
            -- QUESTIONS::
            -- should the list match both specific and wildcard matches?
            -- should the list only match specific first and then do wildcard only if no match
            -- if above is correct, list should be ordered specific first then wildcard so that first match exits the loop
            
            --print(domain_esc)
            for index,list_value in ipairs(lookup_list[domain]) do
                -- this is the counter in the table
                --print(index)
                -- this is the value from the table
                --print(list_value)
                nw.createMeta(self.keys["filter"], list_value)
            end
            
            -- finally aftger writing all the values from the matched value update the  feed.name meta
            -- this throws an error oddly
            nw.createMeta(self.keys["feed.name"], parserName)
        
        end
    end
    --end
end

generic:setCallbacks({
    [nwlanguagekey.create("alias.host")] = generic.onHost,
    [nwlanguagekey.create("fqdn")] = generic.onHost,
    [nwlanguagekey.create("host.src")] = generic.onHost,
    [nwlanguagekey.create("host.dst")] = generic.onHost
})

--return summary