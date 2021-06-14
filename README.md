# pcaprobes
## Extract probe requests from pcap file
### compile:
```gcc main.c -o pcaprobes```

### use:
``` ./pcaprobes capture.pcap | sort | uniq ```
