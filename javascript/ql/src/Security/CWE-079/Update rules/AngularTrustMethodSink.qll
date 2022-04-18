import javascript
import semmle.javascript.security.dataflow.Xss
import semmle.javascript.frameworks.AngularJS.ServiceDefinitions
import semmle.javascript.frameworks.AngularJS.AngularJSCore

class AngularTrustMethodSink extends Shared::Sink {
  AngularTrustMethodSink() {

    exists(ServiceReference service, string methodName, DataFlow::CallNode call |
      service.getName() = "$sce" and
      call.asExpr() = service.getAMethodCall(methodName) and
      (
        methodName = "trustAsJs" or
        methodName = "trustAsHtml" or
        methodName = "trustAsCss" or
        methodName = "trustAs" or
        methodName = "trustAsResourceUrl" or
        methodName = "trustAsUrl"
      ) and
      this = call
    )
    or
    exists(DataFlow::MethodCallNode mce, DataFlow::CallNode call |
      mce.getMethodName() = "element" and
      call = mce.getArgument(0) and
      this = call
    )
  }
}
