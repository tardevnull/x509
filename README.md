# x509

This libray provides an experimental implementation of x509.

The functional differnce from crypto/x509(1.15.2) is :
```
func (c *Certificate) Verify(opts VerifyOptions) (chains [][]*Certificate, err error)
```
This modified Verify function compares issuer with subject by the algorithm described in RFC5280 section-7.

See for more details on comparison algorithm.
https://pkg.go.dev/github.com/tardevnull/dn


Code difference from crypto/x509(1.15.2) is :

```
diff --git a/verify.go b/verify.go
index cb8d8f8..29e032d 100644
--- a/verify.go
+++ b/verify.go
@@ -16,6 +16,7 @@ import (
        "strings"
        "time"
        "unicode/utf8"
+       "github.com/tardevnull/dn"
 )

 // ignoreCN disables interpreting Common Name as a hostname. See issue 24151.
@@ -581,8 +582,11 @@ func (c *Certificate) isValid(certType int, currentChain []*Certificate, opts *V

        if len(currentChain) > 0 {
                child := currentChain[len(currentChain)-1]
-               if !bytes.Equal(child.RawIssuer, c.RawSubject) {
-                       return CertificateInvalidError{c, NameMismatch, ""}
+               if result , err := dn.Compare(child.RawIssuer, c.RawSubject); result != true || err != nil {
+                       if err == nil{
+                               return CertificateInvalidError{c, NameMismatch, ""}
+                       }
+                       return CertificateInvalidError{c, NameMismatch, err.Error()}
                }
        }
 ```
