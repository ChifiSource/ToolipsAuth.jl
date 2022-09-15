<div align="center">
<img src = https://github.com/ChifiSource/image_dump/blob/main/toolips/toolipsauth.png>
<h5>universal authentication for toolips</h5>
</div>


- [Documentation](https://doc.toolips.app/extensions/toolips_auth/)
- [Toolips](https://github.com/ChifiSource/Toolips.jl)
- [Extension Gallery](https://toolips.app/?page=gallery&selected=auth)

Authentication has long been a daunting and problematic task for many developers, but this is no more with toolips. Using this extension, we can create different experiences for different groups just by writing different functions!
- step 1: add toolips auth to your webapp:
```julia
using Toolips
using Pkg

Toolips.new_webapp("MyApp")
Pkg.add("ToolipsAuth")
```
- step 2: add toolips auth to your extension vector:
```julia
routes = [route("/", home), fourofour]
extensions = Vector{ServerExtension}([Logger(), Files(), Session(), Auth()])
```
- step 3: use toolips auth. The `group` method is passed a Connection, String, and Function to produce the high-level syntax. **clients are grouped as 'new' by default.**
```julia
function home(c::Connection)
    group(c, "user") do c::Connection
        write!(c, "this is the user page")
    end
    group(c, "new") do c::Connection
        group!(c, "user", reset = true)
        write!(c, "you are now a user!, click below to reload!")
        b = button("reload", text = "reload")
        on(c, b, "click") do cm::ComponentModifier
            redirect!(cm, "/")
        end
        write!(c, [br(), b])
    end
end
```
