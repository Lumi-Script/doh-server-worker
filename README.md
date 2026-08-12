# Cloudflare DoH Server 
- Supports an Adguard blocklist, available at https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
- Compiles the filter.txt to ts at build
- Forwards X-Forward-For IP to ensure you get local results


[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Lumi-Script/doh-server-worker)

Set build command to: node generate-blocklist.js

Doesn't auto update filter list.

Works with Cloudflare Zerotrust DoH upstream, set it in variable UPSTREAM_DOH. This allows for split DNS (ie local connection onsite, tunnel connection off site).
