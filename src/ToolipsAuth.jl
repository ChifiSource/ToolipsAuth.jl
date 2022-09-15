"""
Created in September, 2022 by
[chifi - an open source software dynasty.](https://github.com/orgs/ChifiSource)
by team
[toolips](https://github.com/orgs/ChifiSource/teams/toolips)
This software is MIT-licensed.
### ToolipsAuth
Provides simple authentication for toolips with client tokens.
##### Module Composition
- [**ToolipsAuth**](https://github.com/ChifiSource/ToolipsAuth.jl)
"""
module ToolipsAuth
using Toolips
import Toolips: ServerExtension, AbstractConnection
using ToolipsSession
using ToolipsSession: gen_ref
using SHA

"""
### Auth <: Toolips.ServerExtension
- type::Vector{Symbol}
- host::String
- port::String
- f::Function
- tokenname::String
- data::Dict{Symbol, Any}
- token_data::Dict{String, Dict{Symbol, Any}}
- client_tokens::Dict{UInt8, String}
- server_data::Dict{Symbol, Any}
- bit::Int64\n
The Auth extension provides a clear seperation between individual clients as
well as data now the server can just store. All in all, this is a very useful
extension. This could be used as the basis for a " login with Google"
implementation, even. `data` holds server data, whereas `token_data` holds client
data. `bit` describes how many bits, divisible by 16, the tokens should be.
##### example
```
function prtoken(c::Connection)
    on(c, "load") do cm::ComponentModifier
        c[:Logger].log(cm["mytoken"]["text"])
    end
end

server = WebServer(extensions = [Auth("mytoken"), Logger()], routes = [Route("/", prtoken)])
server.start()
```
------------------
##### constructors
- Auth(host::String = "127.0.0.1", port::Int64 = 8000; tokenname::String = "auth-token",
provide_tokens::Bool = true, bit::Int64 = 16)
"""
mutable struct Auth <: ServerExtension
    active_routes::Vector{String}
    host::String
    port::Int64
    type::Vector{Symbol}
    f::Function
    server_data::Dict{Symbol, Any}
    client_groups::Dict{String, Vector{String}}
    client_tokens::Dict{Vector{UInt8}, String}
    bit::Int64
    function Auth(active_routes::Vector{String} = ["/"], host::String = "127.0.0.1",
        port::Int64 = 8000;
        tokenname::String = "auth-token", bit::Int64 = 16,
        newconnections::Symbol = :public)
        client_groups = Dict{String, Vector{String}}()
        server_data = Dict{Symbol, Any}(:provide_tokens => true,
        :tokenname => tokenname)
        client_tokens = Dict{Vector{UInt8}, String}()
        f(c::Connection) = begin
            fullpath::String = c.http.message.target
            if contains(c.http.message.target, "?")
                fullpath = split(c.http.message.target, '?')[1]
            end
            if ~(fullpath in active_routes)
                return
            end
            tok::String = ""
            args::AbstractDict = getargs(c)
            if :key in keys(getargs(c))
                tok = args[:key]
            else
                tok = token!(c)
            end
            if server_data[:provide_tokens] == true
                write!(c, token(tokenname, text = tok))
            end
            on(c, "unload") do cm::ComponentModifier

            end
        end
        new(active_routes, host, port, [:func, :connection], f, server_data, client_groups,
         client_tokens, bit)::Auth
    end
end

"""
**Toolips Auth**
### client_token(c::AbstractConnection) -> ::String
------------------
Returns the current client's token.
#### example
```

```
"""
function client_token(c::AbstractConnection)
    tok = c[:Auth].client_tokens[sha256(getip(c))]
end

"""
**Toolips Auth**
### group!(c::AbstractConnection, s::String = "public"; reset::Bool = false)
------------------
groups the client into usergroup `s`. Reset as true will also erase all old
usergroups.
#### example
```

```
"""
function group!(c::AbstractConnection, s::String = "public"; reset::Bool = false)
    if reset
        c[:Auth].client_groups[client_token(c)] = [s]
        return
    end
    push!(c[:Auth].client_groups[client_token(c)], s)
end

"""
**Toolips Auth**
### in_group(c::Connection, group::String) -> ::Bool
------------------
Checks if Connection is in group `group`.
#### example
```

```
"""
in_group(c::Connection, name::String) = name in group(c)

"""
**Toolips Auth**
### group(c::Connection) -> ::Vector{String}
------------------
Gets the groups of the current client.
#### example
```

```
"""
group(c::Connection) = c[:Auth].client_groups[client_token(c)]

"""
**Toolips Auth**
### group(f::Function, c::AbstractConnection, s::String) -> _
------------------
Provide a function and the function will only be performed if `c` is in
    group `s`.
#### example
```
myr = route("/") do c::Connection
    group(c, "public") do c::Connection
        write!(c, "in public!")
    end
    group(c, "first") do c::Connection
        write!(c, "this is your first visit!")
    end
end
```
"""
group(f::Function, c::Connection, s::String) = begin
    if in_group(c, s)
        f(c)
    end
end

"""
**Toolips Auth**
## token!(c::AbstractConnection) -> ::String
------------------
Returns a client's token OR gives a client a new token.
#### example
```

```
"""
token!(c::AbstractConnection) = begin
    bit = c[:Auth].bit
    tok::String = ""
    if sha256(getip(c)) in keys(c[:Auth].client_tokens)
        tokentext = c[:Auth].client_tokens[sha256(getip(c))]
    else
        tok = join([gen_ref() for r in 1:bit/16])
        c[:Auth].client_tokens[sha256(getip(c))] = tok
        group!(c, "new", reset = true)
    end
    tok
end

"""
**Toolips Auth**
### token(name::String, p::Pair{String, Any} ..., args ...) -> ::Component{:token}
------------------
Builds the token `Component`.
#### example
```

```
"""
function token(name::String, p::Pair{String, Any} ...; args ...)
    c::Component{:token} = Component(name, "token", p ..., args ...)
    style!(c, "display" => "none")
    c::Component{:token}
end

"""
**Toolips Auth**
### auth_redirect!(c::Connection, cm::ComponentModifier, s::String, delat::Number = .5)
------------------
Redirects the client with their token as an argument.
#### example
```

```
"""
function auth_redirect!(c::Connection,
    cm::ComponentModifier, s::String, delay::Number = .5)
    key = cm[c[:Auth].server_data[:tokenname]]["text"]
    url = url * "?key=$key"
    redirect!(cm, url, delay)
end

export token, token!, sha256, Auth, group, group!, in_group, client_token
end # module
