"""Builds `polyglot-fixture`: one service per ecosystem (Maven, Gradle, Go, Cargo, Bundler, Composer, NuGet).

Versions are deliberately old so OSV has advisories to match (e.g. log4j-core 2.14.1). Hosts use reserved
`.invalid` names. Nothing here is ever published or built.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>orders</artifactId>
  <version>1.0.0</version>
  <properties>
    <jackson.version>2.9.8</jackson.version>
  </properties>
  <repositories>
    <repository>
      <id>internal</id>
      <url>https://repo.example.invalid/maven</url>
    </repository>
  </repositories>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.12</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
"""
JAVA = """package com.example.orders;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.io.ObjectInputStream;

@RestController
public class OrderController {
    private static final Logger log = LogManager.getLogger(OrderController.class);

    @PostMapping("/orders")
    public String create(String body) throws Exception {
        String key = System.getenv("PAYMENT_API_KEY");
        log.info("order " + body);
        new ObjectInputStream(null).readObject();
        Runtime.getRuntime().exec("report.sh");
        return new ObjectMapper().writeValueAsString(body);
    }
}
"""
GRADLE = """plugins { id 'java' }
repositories {
    mavenCentral()
    maven { url 'https://jitpack.example.invalid' }
}
dependencies {
    implementation 'org.springframework:spring-web:5.2.0.RELEASE'
    testImplementation 'org.junit.jupiter:junit-jupiter:5.7.0'
}
"""
GO_MOD = """module example.com/inventory

go 1.21

require (
\tgithub.com/gin-gonic/gin v1.6.2
\tgolang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 // indirect
)
"""
GO_SUM = """github.com/gin-gonic/gin v1.6.2 h1:88crIK23zO6TqlQBt+f9FrPJNKm9ZEr7qjp9vl/d5TM=
github.com/gin-gonic/gin v1.6.2/go.mod h1:75u5sXoLsGZoRN5Sgbi1eraJ4GU3++wFwWzhwvtwp4M=
golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 h1:psW17arqaxU48Z5kZ0CQnkZWQJsqcURM6tKiBApRjXI=
"""
GO_MAIN = """package main

import (
\t"net/http"
\t"os"
\t"os/exec"

\t"example.com/inventory/internal/store"
\t"github.com/gin-gonic/gin"
)

func main() {
\tr := gin.Default()
\tr.GET("/items", func(c *gin.Context) { c.JSON(http.StatusOK, store.All()) })
\tr.POST("/sync", func(c *gin.Context) {
\t\texec.Command("sync.sh", c.Query("target")).Run()
\t\thttp.Post("https://sync.partner.example.net/push", "application/json", nil)
\t})
\tr.Run(":" + os.Getenv("PORT"))
}
"""
CARGO_TOML = """[package]
name = "pricing"
version = "0.1.0"
edition = "2021"
build = "build.rs"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
smallvec = "=1.6.0"

[dev-dependencies]
criterion = "0.3"
"""
CARGO_LOCK = """version = 3

[[package]]
name = "pricing"
version = "0.1.0"
dependencies = [
 "serde",
 "smallvec",
]

[[package]]
name = "serde"
version = "1.0.100"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "f4473e8506b213730ff2061073b48fa51dcc66349219e2e7c5608f0296a1d95a"
dependencies = [
 "serde_derive",
]

[[package]]
name = "serde_derive"
version = "1.0.100"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "11e410fde43e157d789fc290d26bc940778ad0fdd47836426fbac36573710dbb"

[[package]]
name = "smallvec"
version = "1.6.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1a55ca5f3b68e41c979bf8c46a6f1da892ca4db8f94023ce0bd32407573b1ac0"
"""
RUST_MAIN = """use serde::Serialize;
use smallvec::SmallVec;
use std::process::Command;

#[derive(Serialize)]
struct Price { cents: u64 }

fn main() {
    let db = std::env::var("PRICING_DB_URL").unwrap_or_default();
    let mut v: SmallVec<[u64; 4]> = SmallVec::new();
    v.push(1);
    Command::new("refresh-cache").arg(db).status().ok();
}
"""
GEMFILE = """source 'https://rubygems.org'
source 'https://gems.example.invalid'

gem 'nokogiri', '1.10.0'
gem 'rack', '2.0.1'

group :test do
  gem 'rspec', '3.9.0'
end
"""
GEMFILE_LOCK = """GEM
  remote: https://rubygems.org/
  specs:
    mini_portile2 (2.4.0)
    nokogiri (1.10.0)
      mini_portile2 (~> 2.4.0)
    rack (2.0.1)
    rspec (3.9.0)

PLATFORMS
  ruby

DEPENDENCIES
  nokogiri (= 1.10.0)
  rack (= 2.0.1)
  rspec (= 3.9.0)

BUNDLED WITH
   2.1.4
"""
RUBY_APP = """require 'json'
require 'nokogiri'
require 'rack'
require_relative 'lib/report'

class App
  def call(env)
    token = ENV['REPORT_TOKEN']
    data = Marshal.load(env['rack.input'].read)
    system("convert #{data}")
    [200, {}, [JSON.dump(data)]]
  end
end
"""
RUBY_ROUTES = """Rails.application.routes.draw do
  get '/reports', to: 'reports#index'
  post '/reports/upload', to: 'reports#upload'
end
"""
COMPOSER_JSON = {"name": "example/billing", "require": {"php": ">=7.4", "monolog/monolog": "^2.0", "guzzlehttp/guzzle": "6.5.0"},
                 "require-dev": {"phpunit/phpunit": "^9.0"}, "autoload": {"psr-4": {"Billing\\": "src/"}},
                 "repositories": [{"type": "composer", "url": "https://packages.example.invalid"}]}
COMPOSER_LOCK = {"packages": [
    {"name": "monolog/monolog", "version": "2.0.0",
     "dist": {"type": "zip", "url": "https://api.github.com/repos/Seldaek/monolog/zipball/c861fcba2ca29404dc9e617eedd9eff4616986b8",
              "reference": "c861fcba2ca29404dc9e617eedd9eff4616986b8", "shasum": ""},
     "require": {"php": "^7.2", "psr/log": "^1.0.1"}, "autoload": {"psr-4": {"Monolog\\": "src/Monolog"}}},
    {"name": "psr/log", "version": "1.1.3", "dist": {"type": "zip", "url": "https://api.github.com/repos/php-fig/log/zipball/0f73288fd15629204f9d42b7055f72dacbb811fc",
                                                    "reference": "0f73288fd15629204f9d42b7055f72dacbb811fc", "shasum": ""},
     "autoload": {"psr-4": {"Psr\\Log\\": "Psr/Log/"}}},
    {"name": "guzzlehttp/guzzle", "version": "6.5.0",
     "dist": {"type": "zip", "url": "https://api.github.com/repos/guzzle/guzzle/zipball/dbc2bc3a293ed6b1ae08a3651e2bfd213d19b6a5",
              "reference": "dbc2bc3a293ed6b1ae08a3651e2bfd213d19b6a5", "shasum": ""},
     "autoload": {"psr-4": {"GuzzleHttp\\": "src/"}}}],
    "packages-dev": [{"name": "phpunit/phpunit", "version": "9.0.0",
                      "dist": {"type": "zip", "url": "https://api.github.com/repos/sebastianbergmann/phpunit/zipball/abc", "reference": "abc", "shasum": ""},
                      "autoload": {"classmap": ["src/"]}}]}
PHP_APP = """<?php
namespace Billing;

use Monolog\\Logger;
use GuzzleHttp\\Client;
use Billing\\Invoice;

Route::post('/invoices', function () {
    $key = getenv('BILLING_SECRET');
    $data = unserialize($_POST['payload']);
    shell_exec('pdf ' . $data);
    (new Client())->post('https://tax.partner.example.net/calc');
});
"""
CSPROJ = """<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
    <PackageReference Include="xunit" Version="2.4.1" PrivateAssets="all" />
  </ItemGroup>
</Project>
"""
NUGET_LOCK = {"version": 1, "dependencies": {"net8.0": {
    "Newtonsoft.Json": {"type": "Direct", "requested": "[12.0.1, )", "resolved": "12.0.1", "contentHash": "pBR3wCgYWZGiaZDYP+HHYnalVnPJlpP1q55qvVb+adrDHmFMDc1NAKio61xTwftK3Pw5h7TZJPJEEVMf6ty="},
    "xunit": {"type": "Direct", "requested": "[2.4.1, )", "resolved": "2.4.1", "contentHash": "XNR3Yz9QTtec16O0aKcO6+baVNpXmOnPUxDkCY97J+8krUYxPvXT1szYYEUdKk4sB8GOI2YbAjRIOm8ZnXRfzQ==",
              "dependencies": {"xunit.core": "[2.4.1]"}},
    "xunit.core": {"type": "Transitive", "resolved": "2.4.1", "contentHash": "Zsj5OMU6JasNGERXZy8s72+pcheG6Q15atS5XpZXqAtULuyQiQ6XNnUsp1gyfC6WgqScqMvySiEHmHcOG6Eg0Q=="}}}}
CSHARP = """using System;
using System.Diagnostics;
using Newtonsoft.Json;
using Shipping.Domain;

namespace Shipping.Api
{
    [ApiController]
    public class LabelsController
    {
        [HttpPost("labels")]
        public string Create(string body)
        {
            var key = Environment.GetEnvironmentVariable("CARRIER_KEY");
            var obj = JsonConvert.DeserializeObject(body, new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All });
            Process.Start("print-label", body);
            return key;
        }
    }
}
"""

FILES = {
    "README.md": "# polyglot-fixture\n\nOne small service per ecosystem, used to test Guardian beyond Python and JavaScript.\n",
    "java-orders/pom.xml": POM,
    "java-orders/src/main/java/com/example/orders/OrderController.java": JAVA,
    "kotlin-web/build.gradle": GRADLE,
    "go-inventory/go.mod": GO_MOD, "go-inventory/go.sum": GO_SUM, "go-inventory/main.go": GO_MAIN,
    "go-inventory/internal/store/store.go": "package store\n\nfunc All() []string { return nil }\n",
    "rust-pricing/Cargo.toml": CARGO_TOML, "rust-pricing/Cargo.lock": CARGO_LOCK, "rust-pricing/src/main.rs": RUST_MAIN,
    "rust-pricing/build.rs": "fn main() {}\n",
    "ruby-reports/Gemfile": GEMFILE, "ruby-reports/Gemfile.lock": GEMFILE_LOCK, "ruby-reports/app.rb": RUBY_APP,
    "ruby-reports/config/routes.rb": RUBY_ROUTES, "ruby-reports/lib/report.rb": "class Report; end\n",
    "php-billing/composer.json": json.dumps(COMPOSER_JSON, indent=2), "php-billing/composer.lock": json.dumps(COMPOSER_LOCK, indent=2),
    "php-billing/src/routes.php": PHP_APP,
    "dotnet-shipping/Shipping.Api.csproj": CSPROJ, "dotnet-shipping/packages.lock.json": json.dumps(NUGET_LOCK, indent=2),
    "dotnet-shipping/LabelsController.cs": CSHARP,
    "dotnet-shipping/nuget.config": '<?xml version="1.0"?>\n<configuration><packageSources>'
                                    '<add key="nuget.org" value="https://api.nuget.org/v3/index.json" />'
                                    '<add key="internal" value="https://nuget.example.invalid/v3/index.json" />'
                                    '</packageSources></configuration>\n',
    "Dockerfile": "FROM golang:1.20\nWORKDIR /src\nCOPY go-inventory .\nRUN go get ./...\nCMD [\"/src/inventory\"]\n",
}


def make_polyglot_fixture(dest: Path) -> Path:
    root = Path(dest) / "polyglot-fixture"
    if root.exists():
        shutil.rmtree(root, onerror=lambda f, p, e: (os.chmod(p, 0o700), f(p)))
    for path, content in FILES.items():
        p = root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8", newline="\n")
    env = dict(os.environ, GIT_AUTHOR_DATE="2026-11-20T10:00:00Z", GIT_COMMITTER_DATE="2026-11-20T10:00:00Z")
    base = ["git", "-c", "user.name=Fixture Bot", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false"]
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True, capture_output=True)
    subprocess.run(base + ["add", "-A"], cwd=root, check=True, capture_output=True, env=env)
    subprocess.run(base + ["commit", "-q", "-m", "polyglot baseline"], cwd=root, check=True, capture_output=True, env=env)
    return root
