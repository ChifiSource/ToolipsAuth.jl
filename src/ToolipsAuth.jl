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
    port::String
    type::Vector{Symbol}
    f::Function
    server_data::Dict{Symbol, Any}
    client_groups::Dict{String, Vector{Vector{UInt8}}}
    clients::Dict{Vector{UInt8}, String}
    bit::Int64
    function Auth(active_routes::Vector{String} = ["/"], host::String = "127.0.0.1",
        port::Int64 = 8000;
        tokenname::String = "auth-token", bit::Int64 = 16,
        newconnections::Symbol = :public)
        client_groups = Dict{String, Vector{String}}()
        server_data = Dict{Symbol, Any}(:provide_tokens => true,
        :tokenname => tokenname)
        client_tokens = Dict{UInt8, String}()
        f(c::Connection) = begin
            fullpath::String = http.message.target
            if contains(http.message.target, "?")
                fullpath = split(http.message.target, '?')[1]
            end
            if ~(fullpath in active_routes)
                return
            end
            token::String = ""
            args::AbstractDict = getargs(c)
            if :key in keys(getargs(c))
                token = args[:key]
            else
                token = token!(c)
            end
            if server_data[:provide_tokens] == true
                write!(c, token)
            end
            on(c, "unload") do cm::ComponentModifier

            end
        end
        new(host, port, [:func, :connection], f, server_data )::AuthData
    end
end

function client_token(c::AbstractConnection)
    token = c[:Auth].clients[sha256(getip(c))]
end

function group!(c::AbstractConnection, s::String = "public"; reset::Bool = false)
    groups = c[:Auth].client_groups
    if reset
        groups = Dict{String, String}()
    end
    push!(groups[client_token(c)], s)
end

in_group(c::Connection, group::String) = group in group(c)

group(c::Connection) = c[:Auth].client_groups[client_token(c)][:group]

group(f::Function, c::Connection, s::String) = begin
    if in_group(c, s)
        f(c)
    end
end

token!(c::AbstractConnection) = begin
    bit = c[:Auth].bit
    token::String = ""
    if sha256(getip(c)) in keys(c[:Auth].clienttokens)
        tokentext = c[:Auth].client_tokens[sha256(getip(c))]
    else
        token = join([gen_ref() for r in 1:bit/16])
        c[:Auth].client_tokens[sha256(getip(c))] = token
        group!(c, "new")
    end
    token
end

function token(name::String, p::Pair{String, Any} ...; args ...)
    c::Component{:token} = Component(name, "token", p ... args ...)
    style!(c, "display" => "none")
    c::Component{:token}
end

function auth_redirect!(c::Connection,
    cm::ComponentModifier, s::String, delay::Number = .5)
    key = cm[c[:Auth].server_data[:tokenname]]["text"]
    url = url * "?key=$key"
    redirect!(cm, url, delay)
end

export token, token!, sha256, Auth
end # module
