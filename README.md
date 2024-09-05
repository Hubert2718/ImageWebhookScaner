Goal is to provide image scanner which will automatically scan images before allowing them to be deployed on cluster. To achieve this I have written simple go script, which inside runs `trivy image` scan, and rejects this with `CRITICAL` vulnerabilities.

Script can be run as pod on cluster, to deploy it use provided helm chart. 

As it works as `ImagePolicyWebhook` you will also need to add additional configuration on your cluster.

### Webhook Server Certificates

```bash
openssl genrsa -out webhook-server.key 2048
openssl req -new -key webhook-server.key -subj "/CN=system:node:imagepolicywebhook/O=system:nodes" -addext "subjectAltName = DNS:imagepolicywebhook.imagepolicywebhook.svc.cluster.local,DNS:imagepolicywebhook.imagepolicywebhook.svc,DNS:imagepolicywebhook.imagepolicywebhook.pod.cluster.local,IP:$SERVICE_IP" -out webhook-server.csr 
```

- `imagepolicywebhook.imagepolicywebhook.svc`  is DNS entry for our service (check provided helm chart), if you will name it otherwise here is hint: `<namespace>.<service_name>.svc`

First command is used to create our our private key for certificate.

Second one is used to CSR (Certificate Sign Request) encrypted with our `webhook-server.key`

Now we will approve and sign our CSR  with use of `CertificateSignRequest` and `kubectl certificateapprove` command.

First lets get base64 encoded `webhook-server.csr` :

```bash
cat webhook-server.csr | base64 | tr -d "\n"
```

Then we will need to create `CertificateSigningRequest` kubernetes object:

```yaml
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: webhook-server
spec:
  request: <YOUR_BAS64_ENCODED_CSR>
  signerName: kubernetes.io/kubelet-serving
  expirationSeconds: 864000  # ten days
  usages:
  - digital signature
  - key encipherment
  - server auth
```

and approve it:

```yaml
kubectl certificate approve webhook-server
```

We need to get certificate created in the process:

```yaml
kubectl get csr webhook-server -o=jsonpath={.status.certificate} | base64 --decode > webhook-server.crt

```

We need to mount both `.key` and `.crt` files to pod serving as  webhook server. As mounting code is already present in helm chart, only thing you need to do is:

```yaml
kubectl create secret tls webhook-server --cert=webhook-server.crt --key=webhook-server.key -n imagepolicywebhook
```

Now your pods should be up and running.

### Api server configurations

First create directory

```yaml
sudo mkdir -p /etc/kubernetes/webhook
```

and copy `.crt`  there:

```yaml
sudo cp webhook-server.crt /etc/kubernetes/webhook
```

Create kubeconfig file which will allow for webhook and apiserver communications :

```yaml
sudo vim /etc/kubernetes/webhook/webhook.yaml
```

remember about adjusting `<CLUSTER_IP_OF_YOUR_SVC>` with value of created svc from helm chart.

```yaml
apiVersion: v1
clusters:
- cluster:
    certificate-authority: /etc/kubernetes/webhook/webhook-server.crt
    server: https://<CLUSTER_IP_OF_YOUR_SVC>
  name: webhook
contexts:
- context:
    cluster: webhook
    user: imagepolicywebhook.imagepolicywebhook.svc
  name: webhook
current-context: webhook
kind: Config
users:
- name: imagepolicywebhook.imagepolicywebhook.svc
  user:
    client-certificate: /etc/kubernetes/pki/apiserver.crt
    client-key: /etc/kubernetes/pki/apiserver.key
```

and configuration file:

```yaml
sudo vim /etc/kubernetes/webhook/admissionConfig.yaml
```

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
  - name: ImagePolicyWebhook
    configuration:
      imagePolicy:
        kubeConfigFile: /etc/kubernetes/webhook/webhook.yaml
        allowTTL: 50
        denyTTL: 50
        retryBackoff: 500
        defaultAllow: false
        timeoutSeconds: 120
```

### Edit kube-api manifest

IMPORTANT: create backup before this, every misconfiguration cause api-server not comping back ⇒ you will not be able to see logs via `kubectl` commands, or do mostly anything regarding cluster

```yaml
sudo cp /etc/kubernetes/manifests/kube-apiserver.yaml .
```

edit api-server manifest like below:

```yaml
sudo vim /etc/kubernetes/manifests/kube-apiserver.yaml
```

```yaml
    - --enable-admission-plugins=ImagePolicyWebhook
    - --admission-control-config-file=/etc/kubernetes/webhook/admissionConfig.yaml

    volumeMounts:
    - mountPath: /etc/kubernetes/webhook
      name: webhook
      readOnly: true

  - hostPath:
      path: /etc/kubernetes/webhook/
      type: DirectoryOrCreate
    name: webhook
```

Wait for api-server to restart.

### Test

Now we will try to start a pod with vulnerabilities:

```yaml
k run pod --image=docker.io/nginx
```

as you can see, we are not allowed to do this:

```yaml
Error from server (Forbidden): pods "pod" is forbidden: image policy webhook backend denied one or more images: image docker.io/nginx has vulnerabilities
```

can check our `image-policy-webhook` pods for logs to get specific details about vulnerabilities:

```yaml
Running Trivy scan for image: docker.io/nginx
[2024-09-05T14:19:53Z] Critical Vulnerability Found:
  - Vulnerability ID: CVE-2023-6879
  - Package Name: libaom3
  - Installed Version: 3.6.0-1+deb12u1
  - Severity: CRITICAL
  - Description: Increasing the resolution of video frames, while performing a multi-threaded encode, can result in a heap overflow in av1_loop_restoration_dealloc().

[2024-09-05T14:19:53Z] Critical Vulnerability Found:
  - Vulnerability ID: CVE-2024-45490
  - Package Name: libexpat1
  - Installed Version: 2.5.0-1
  - Severity: CRITICAL
  - Description: An issue was discovered in libexpat before 2.6.3. xmlparse.c does not reject a negative length for XML_ParseBuffer.
[2024-09-05T14:19:53Z] Critical Vulnerability Found:
  - Vulnerability ID: CVE-2024-45491
  - Package Name: libexpat1
  - Installed Version: 2.5.0-1
  - Severity: CRITICAL
  - Description: An issue was discovered in libexpat before 2.6.3. dtdCopy in xmlparse.c can have an integer overflow for nDefaultAtts on 32-bit platforms (where UINT_MAX equals SIZE_MAX).
[2024-09-05T14:19:53Z] Critical Vulnerability Found:
  - Vulnerability ID: CVE-2024-45492
  - Package Name: libexpat1
  - Installed Version: 2.5.0-1
  - Severity: CRITICAL
  - Description: An issue was discovered in libexpat before 2.6.3. nextScaffoldPart in xmlparse.c can have an integer overflow for m_groupSize on 32-bit platforms (where UINT_MAX equals SIZE_MAX).
[2024-09-05T14:19:53Z] Critical Vulnerability Found:
  - Vulnerability ID: CVE-2023-45853
  - Package Name: zlib1g
  - Installed Version: 1:1.2.13.dfsg-1
  - Severity: CRITICAL
  - Description: MiniZip in zlib through 1.3 has an integer overflow and resultant heap-based buffer overflow in zipOpenNewFileInZip4_64 via a long filename, comment, or extra field. NOTE: MiniZip is not a supported part of the zlib product. NOTE: pyminizip through 0.2.6 is also vulnerable because it bundles an affected zlib version, and exposes the applicable MiniZip code through its compress API.
[2024-09-05T14:19:53Z] No critical vulnerabilities found for image: docker.io/nginx
[2024-09-05T14:19:55Z] Critical Vulnerability Found:
  - Vulnerability ID: CVE-2023-6879
  - Package Name: libaom3
  - Installed Version: 3.6.0-1+deb12u1
  - Severity: CRITICAL
  - Description: Increasing the resolution of video frames, while performing a multi-threaded encode, can result in a heap overflow in av1_loop_restoration_dealloc().
```

### Annotations

You can skip image scan by adding annotation to pod:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
  namespace: default
  annotations:
    mycluster.image-policy.k8s.io/ticket-1234: "break-glass"
spec:
  containers:
    - name: my-container
      image: myrepo/myimage:v1
```

- Annotation key format: `*.image-policy.k8s.io/*`
- must be: `"break-glass"`
