module ToolipsAuth
using Toolips
import Toolips: ServerExtension, AbstractConnection
using ToolipsSession
using ToolipsSession: gen_ref
using SHA
using JLD2

mutable struct Authenticator <: ServerExtension
    type::Vector{Symbol}
    f::Function
    tokenname::String
    token_data::Dict{String, Dict{Symbol, Any}}
    clienttokens::Vector{UInt8, String}
    requests::Vector{UInt8, Int64}
    identifiers::Dict{Pair{String, UInt8}}
    bit::Int64
    function Authenticator(tokenname::String; bit::Int64 = 16)
        if ~(bit % 16 == 0)
            throw("Authenticator bit not divisible by 16!")
        end
        token_data =
        f(c::Connection) = begin

        end
        new([:func, :connection], f, active_routes)::AuthData
    end
end

token!(c::AbstractConnection) = begin
    bit = c[:Authenticator].bit
    token::String = ""
    if sha256(getip(c)) in keys(c[:Authenticator].clienttokens)

    else
        token = join([gen_ref() for r in 1:bit/16])
        c[:Authenticator].clienttokens[sha256(getip(c))] = token
    end
end

function token(c::Connection, name::String, p::Pair{String, String}; args ...)
    Component(name, token, )
end
end # module
