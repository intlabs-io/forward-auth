# Kubernetes Deployment

The manifests directory contains Kustomize scripts for the deployment
of forward-auth to a Kubernetes cluster. The prerequsites are an installation
of Traefik (obviously) and kubeseal. 

*Your must create a Kustomize overlay that modifies the scripts in base.*

The manifests assume a deployment to a namespace named "apis." This is the
namepace where your Web applications and APIs are deployed. If that is not the
namespace you are using (and why would it be) then you must kustomize
middleware.yaml to use the correct internal address defining the
forward-auth /auth endpoint. Replace "apis" with the namespace where your
APIs are deployed and thereforce where forward-auth will be deployed:

```
# Forward authorization requests to forward-auth host in cluster 
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: forward-auth-middleware
spec:
  forwardAuth:
    address: http://forward-auth-service.apis.svc.cluster.local:8080/auth
```

Notice the appearance of the ```apis``` namespace in the address above. This allows
direct HTTP requests from inside the Kubernetes cluster without additional
routing.

To use the correct namespace - let's say ```my-apis``` - for your application
create a patch file like the following:

```
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: forward-auth-middleware
spec:
  forwardAuth:
    address: http://forward-auth-service.my-apis.svc.cluster.local:8080/auth
```
Then edit the kustomization file for your overlay to apply the patch:

```
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: my-apps
resources:
- namespace.yaml
- https://bitbucket.org/_metalogic_/forward-auth/manifests
- etc ...
patchesStrategicMerge:
- forward-auth-middleware.yaml
```
