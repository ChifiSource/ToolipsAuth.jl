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
##### examples
- **client tokens**

The following example demonstrates logging the client's token into console `on`
load with ToolipsSession:
```
using Toolips
using ToolipsSession
using ToolipsAuth


function prtoken(c::Connection)
    on(c, "load") do cm::ComponentModifier
        c[:Logger].log(cm["mytoken"]["text"])
    end
end

server = WebServer(extensions = [Auth("mytoken"), Logger()], routes = [Route("/", prtoken)])
server.start()
```
Here is another example, were we build a simple login by using SHA to store login
details inside of our outer-module scope. Note that this requires an additional
change to our `dev.jl` and/or `prod.jl` environments.
- add to **dev.jl**:
```
HOSTNAME = "127.0.0.1"
USERS = Dict{String, Vector{UInt8}}()
```
These will be our globally defined variables, if we wanted to we could even task
a system to save this with `JLD2`, write it into some data format, push to a db,
what have you. This will soon be made easier, as well, with the refinement of
`ToolipsRemote` onto `ToolipsManager`. Back to the project, we need our route to
allow new users to provide user data. For now it will just be a username and a
password, hence how the `Dict` is so simple.
- rewrite **home** in your source file:
```
using Toolips
using ToolipsSession
using ToolipsAuth
using ToolipsDefaults: textdiv, sheet

home = route("/") do c::Connection
    write!(c, sheet())
    group(c, "new") do c::Connection
        # username/pwd box
        usernamebox = textdiv("usernamebox")
        pwdbox = textdiv("mytxtdiv")
        my_logo = h(1, "mylogo", text = "The Pink Balloon Club")
        submitbutton = button("submitbutton" text = "login")
        on(c, submitbutton, "click") do cm::ComponentModifier

        end
        lower_div = div("lowrdi", align = "center")
        upper_div = div("upprdi", align = "center")
        style!(upper_div, "margin-top" => 50percent, "padding" => 20px,
        background-color => #84F04F)
        bod = body("main-body")
        push!(bod, upper_div, lower_div)
        write!(c, )
    end
end

register = route("/") do c::Connection
    write!(c, sheet())

end
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
    authlinks::Dict{String, Vector{String}}
    client_info::Dict{String, Dict{String, Any}}
    client_tokens::Dict{Vector{UInt8}, String}
    bit::Int64
    function Auth(active_routes::Vector{String} = ["/"], host::String = "127.0.0.1",
        port::Int64 = 8000;
        tokenname::String = "auth-token", bit::Int64 = 16,
        default_group::String = "public", save::Bool = false)
        client_info = Dict{String, Vector{String}}()
        server_data = Dict{Symbol, Any}(:provide_tokens => true,
        :tokenname => tokenname)
        client_tokens = Dict{Vector{UInt8}, String}()
        authlinks::Dict{String, Vector{String}} = Dict{String, Vector{String}}()
        f(c::Connection) = begin
            if save == true
                
            end
            fullpath::String = c.http.message.target
            if contains(c.http.message.target, "?")
                fullpath = split(c.http.message.target, '?')[1]
            end
            if ~(fullpath in active_routes)
                return
            end
            tok::String = ""
            args::AbstractDict = getargs(c)
            if :key in keys(args)
                tok = args[:key]
                if tok in authlinks
                    delete!(authlinks, tok)
                    client_tokens[sha256(getip(c))] = tok
                end
            else
                tok = token!(c)
            end
            if server_data[:provide_tokens] == true
                write!(c, token(tokenname, text = tok))
            end
            on(c, "unload") do cm::ComponentModifier
                #== TODO Store authenticated data, remove the current key
                    Perhaps allow a closure to run? I am not exactly sure
                    where I want to take it. :D
                ==#
            end
        end
        new(active_routes, host, port, [:func, :connection], f, server_data,
        authlinks, client_groups,
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


"""
**Toolips Auth**
### auth_link!(c::Connection, group::Vector{String}, hostname::String)
------------------
Generates an authenticated link for hostname and returns key to give that group.
#### example
Here we write a link that auto authenticates. Alternatively, we
could also use `group!` here. Try `?(group!)` and `?(group)` for more
information on this.
Another alternative is group! and/or auth_redirect! on a `ComponentModifier.`
```
using Toolips
using ToolipsAuth
#== This would ideally be an environmental variable,
   You could put this into dev.jl if you wanted to ! ==#
HOST = "127.0.0.1"
home = route("/") do c::Connection
    # If the user is new to the server by IP, then we serve them this:
    group(c, "new") do c::Connection
        write!(c, "you're not authenticated, click this link: ")
        write!(c, auth_link!(c, ["user"], HOST))
    end
    # If they are authenticated via this link, we serve them this:
    group(c, "user") do c::Connection
        write!(c, "now you are authenticated.")
    end
end
```
"""
function auth_link!(c::Connection, group::Vector{String},
    hostname::String)
    key::String = join([gen_ref() for r in 1:c[:Auth].bit/16])
    c[:Auth].authlinks[key] = group
    return("https://$hostname/?key=$key")
end

export token, token!, sha256, Auth, group, group!, in_group, client_token
export auth_link!, auth_redirect!
end # module
