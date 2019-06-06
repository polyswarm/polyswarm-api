# Notes on how to use Sphinx (T.E.)


## Autogenerate API docs

Default way to autogenerate API docs for $Module

`sphinx-apidoc -o source/ ../src/$MODULE`

## Raw Directives

I needed a way to actually inject raw HTML into the RST so it didn't appear in the sidebar. Hence:

```
.. raw:: html

    <h2>Submodules</h2>

```
### Resources

[Good blog post on Sphinx](https://samnicholls.net/2016/06/15/how-to-sphinx-readthedocs/)
[reStructuredText_ Cheat Sheet](http://docutils.sourceforge.net/docs/user/rst/cheatsheet.txt)