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
import OddStructures: AbstractDimensions
import Toolips: ServerExtension, AbstractConnection
using ToolipsSession
using ToolipsSession: gen_ref
using SHA
using JLD2

"""
### Name
- text::String \
Description
##### example
```

```
------------------
##### field info

------------------
##### constructors

"""
mutable struct UserGroup{s <: Symbol}
    UserGoup(name::String) = new{Symbol(name)}()
end

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
    host::String
    port::String
    type::Vector{Symbol}
    f::Function
    data::Dict{Symbol, Any}
    client_data::Dict{Vector{UInt8}, Dict{Symbol, Any}}
    clients::Dict{UInt8, String}
    bit::Int64
    function Auth(host::String = "127.0.0.1", port::Int64 = 8000,
        tokenname::String = "auth-token", bit::Int64 = 16)
        client_data = Dict{String, Dict{Symbol, Any}}()
        server_data = Dict{Symbol, Any}(:blacklist => Vector{Vector{UInt8}}(),
        :provide_tokens => true, :tokenname => tokenname)
        client_tokens = Dict{UInt8, String}()
        f(c::Connection) = begin
            if c[:Auth].client_tokens[sha256(getip(c))] in server_data[:blacklist]
                return
            end
            token = token!(c)
            if server_data[:provide_tokens] == true
                write!(c, token)
            end
            on(c, "unload") do cm::ComponentModifier

            end
        end
        new(host, port, [:func, :connection], f, server_data )::AuthData
    end
end

register!(c::AbstractConnection, d::Pair{Any, Any} ...) =  begin
    ipidentifier = sha256(getip(c))
    push!()
end

save_clients!(c::AbstractConnection, path::String) = begin

end

save_server!(c::AbstractConnection, path::String) = begin

end

authlink!(ts::Toolips.ToolipsServer) = begin

end

function auth_redirect!(cm::ComponentModifier, s::String)

end

function auth_spawn!()

end

token!(c::AbstractConnection) = begin
    bit = c[:Auth].bit
    token::String = ""
    if sha256(getip(c)) in keys(c[:Auth].clienttokens)
        tokentext = c[:Auth].client_tokens[sha256(getip(c))]
        write!(c, token(c[:Auth].tokenname, text = tokentext))
    else
        token = join([gen_ref() for r in 1:bit/16])
        c[:Auth].client_tokens[sha256(getip(c))] = token
        group!(c, "public")
    end
    token
end

function group!(c::Connection, s::String)

end

function authenticate!(f::Function, c::AbstractConnection)

end

function token(name::String, p::Pair{String, Any} ...; args ...)
    c::Component{:token} = Component(name, "token", p ... args ...)
    style!(c, "display" => "none")
    c::Component{:token}
end

export token, token!, sha256, Auth
end # module
