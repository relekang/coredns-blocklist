# coredns-blocklist

This is a [coredns][] plugin to return NXDOMAIN response for any domain
on preloaded lists. It can be useful to block malware domains or trackers.

## Usage

It is possible to use this plugin with both files from disk and fetch
files from http servers by passing an url. The file should contain one
domain on each line. There is an example file in the example folder.

```
. {
  log
  prometheus

  # load from url
  blocklist https://mirror1.malwaredomains.com/files/justdomains
  # load from file, if the path is not absolute it will be relative to the Corefile
  blocklist list.txt

  forward . 1.1.1.1 1.0.0.1
}
```

## Installation

There is multiple ways to add plugins in [coredns][], but no matter the
way you choose **the order matters**. The order sets the precedense of
the plugins when resolving queries. This means the blocklist plugin
should be before any plugins that would resolve the domains correctly.
Furthermore, the log plugin should be before this plugin to get proper
logging.

### Using plugin.cfg file

Add the following to the plugin.cfg file in your clone of coredns and follow
the instructions from coredns.

```
blocklist:github.com/relekang/coredns-blocklist
```

### Using a go file to compile the bundle

See the [example/main.go](./example/main.go) for how to create a file that you
can compile to get coredns with this plugin. This file will work with the
coredns version defined in [go.mod](./go.mod).

The example is bundled up with releases of on the [release page][] of this
repository. There it can be downloaded prebuilt for a bunch of environments.

[coredns]: https://coredns.io
[release page]: https://github.com/relekang/coredns-blocklist/releases
