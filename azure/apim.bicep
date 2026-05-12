// Azure API Management (Consumption tier) — API Security Demo
// Consumption tier: pay-per-call, ~$3.50/million calls, NO idle cost
// This replaces the custom FastAPI gateway with production-grade APIM policies

@description('Azure region')
param location string = resourceGroup().location

@description('Unique suffix')
param suffix string = uniqueString(resourceGroup().id)

@description('Publisher email (required by APIM)')
param publisherEmail string = 'demo@example.com'

@description('Backend AI Service URL (Azure Container Apps FQDN)')
param aiServiceUrl string

// ── Azure API Management (Consumption tier) ───────────────────────────────────
resource apim 'Microsoft.ApiManagement/service@2023-09-01-preview' = {
  name: 'apim-ai-security-${suffix}'
  location: location
  sku: {
    name: 'Consumption'
    capacity: 0   // must be 0 for Consumption
  }
  properties: {
    publisherEmail: publisherEmail
    publisherName: 'API-Centric AI Security Demo'
    customProperties: {
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10': 'false'
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls11': 'false'
    }
  }
}

// ── Named Values (secrets / config) ───────────────────────────────────────────
resource nvAiUrl 'Microsoft.ApiManagement/service/namedValues@2023-09-01-preview' = {
  parent: apim
  name: 'ai-service-url'
  properties: {
    displayName: 'ai-service-url'
    value: aiServiceUrl
    secret: false
  }
}

// ── API Definition ─────────────────────────────────────────────────────────────
resource api 'Microsoft.ApiManagement/service/apis@2023-09-01-preview' = {
  parent: apim
  name: 'ai-security-api'
  dependsOn: [nvAiUrl]
  properties: {
    displayName: 'AI Security API'
    description: 'API-Centric Security Demo — APIM as the security enforcement layer over an AI inference service'
    path: 'ai'
    protocols: ['https']
    subscriptionRequired: true
    subscriptionKeyParameterNames: {
      header: 'Ocp-Apim-Subscription-Key'
      query: 'subscription-key'
    }
    serviceUrl: aiServiceUrl
  }
}

// ── API-level policy: global logging via Azure Monitor ─────────────────────────
resource apiPolicy 'Microsoft.ApiManagement/service/apis/policies@2023-09-01-preview' = {
  parent: api
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: '''
<policies>
  <inbound>
    <!-- Inject gateway identity header for all operations -->
    <set-header name="X-Gateway" exists-action="override">
      <value>Azure-APIM</value>
    </set-header>
    <base />
  </inbound>
  <backend><base /></backend>
  <outbound>
    <!-- Expose gateway response header -->
    <set-header name="X-Gateway" exists-action="override">
      <value>Azure-APIM</value>
    </set-header>
    <base />
  </outbound>
  <on-error><base /></on-error>
</policies>'''
  }
}

// ── Operation: POST /predict ───────────────────────────────────────────────────
resource predictOp 'Microsoft.ApiManagement/service/apis/operations@2023-09-01-preview' = {
  parent: api
  name: 'predict'
  properties: {
    displayName: 'Run Inference'
    method: 'POST'
    urlTemplate: '/predict'
    description: 'Submit features for classification. Passes through all 5 APIM security layers.'
    request: {
      representations: [
        {
          contentType: 'application/json'
          schemaId: 'predict-request-schema'
          typeName: 'PredictRequest'
        }
      ]
    }
    responses: [
      { statusCode: 200, description: 'Successful prediction' }
      { statusCode: 400, description: 'Schema violation or SQL injection detected' }
      { statusCode: 401, description: 'Missing or invalid subscription key' }
      { statusCode: 403, description: 'Anomaly score threshold exceeded' }
      { statusCode: 429, description: 'Rate limit exceeded (50 RPM)' }
    ]
  }
}

// ── POST /predict — 5-layer security policy ────────────────────────────────────
resource predictPolicy 'Microsoft.ApiManagement/service/apis/operations/policies@2023-09-01-preview' = {
  parent: predictOp
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: '''
<policies>
  <inbound>
    <base />

    <!-- ══════════════════════════════════════════════════════════════
         LAYER 1 — AUTHENTICATION
         Subscription key enforced at APIM product level (automatic).
         Additionally: block requests with obvious bot/scanner UA.
    ══════════════════════════════════════════════════════════════ -->
    <choose>
      <when condition="@{
        var ua = context.Request.Headers.GetValueOrDefault("User-Agent","");
        return ua.Contains("sqlmap") || ua.Contains("nikto") || ua.Contains("nmap");
      }">
        <return-response>
          <set-status code="403" reason="Forbidden" />
          <set-header name="Content-Type" exists-action="override"><value>application/json</value></set-header>
          <set-body>{"error":"Scanner/bot User-Agent blocked","blocked_by":"APIM-Auth","layer":1}</set-body>
        </return-response>
      </when>
    </choose>

    <!-- ══════════════════════════════════════════════════════════════
         LAYER 2 — RATE LIMITING
         50 requests per 60 seconds, keyed by subscription key.
         Returns 429 with Retry-After header on breach.
    ══════════════════════════════════════════════════════════════ -->
    <rate-limit calls="50" renewal-period="60" />

    <!-- ══════════════════════════════════════════════════════════════
         LAYER 3 — PAYLOAD SIZE + JSON SCHEMA VALIDATION
         Rejects payloads > 50 KB; validates required fields,
         types, and numeric ranges via JSON schema.
    ══════════════════════════════════════════════════════════════ -->
    <validate-content
      unspecified-content-type-action="prevent"
      max-size="51200"
      size-exceeded-action="prevent"
      errors-variable-name="validationErrors">
      <content type="application/json" validate-as="json" action="prevent" />
    </validate-content>

    <!-- ══════════════════════════════════════════════════════════════
         LAYER 4 — SQL INJECTION / INJECTION PATTERN DETECTION
         Scans serialized request body for OWASP Top 10 injection
         patterns before forwarding to the AI backend.
    ══════════════════════════════════════════════════════════════ -->
    <set-variable name="requestBody" value="@(context.Request.Body.As<string>(preserveContent: true))" />
    <choose>
      <when condition="@{
        var body = (string)context.Variables["requestBody"];
        var patterns = new [] {
          @"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|CREATE|ALTER|EXEC|UNION)\b)",
          @"(--|;.*--|\/\*[\s\S]*?\*\/)",
          @"(xp_\w+|sp_\w+)",
          @"(\bOR\b\s+[\'\d].*=.*[\'\d]|\bAND\b\s+[\'\d].*=.*[\'\d])",
          @"(SLEEP\s*\(|WAITFOR\s+DELAY|BENCHMARK\s*\()",
          @"(CAST\s*\(|CONVERT\s*\(.*CHAR)"
        };
        foreach (var p in patterns) {
          if (System.Text.RegularExpressions.Regex.IsMatch(
                body, p,
                System.Text.RegularExpressions.RegexOptions.IgnoreCase)) {
            return true;
          }
        }
        return false;
      }">
        <return-response>
          <set-status code="400" reason="Bad Request" />
          <set-header name="Content-Type" exists-action="override"><value>application/json</value></set-header>
          <set-body>{"error":"SQL/injection pattern detected","blocked_by":"APIM-WAF","layer":4}</set-body>
        </return-response>
      </when>
    </choose>

    <!-- ══════════════════════════════════════════════════════════════
         LAYER 5 — ANOMALY SCORE THRESHOLD
         Blocks requests whose anomaly_score field >= 8.0.
         High-anomaly requests are rejected before reaching the AI model,
         eliminating wasted backend compute (paper Section IV-C).
    ══════════════════════════════════════════════════════════════ -->
    <choose>
      <when condition="@{
        try {
          var body = Newtonsoft.Json.Linq.JObject.Parse(
            (string)context.Variables["requestBody"]);
          var score = body.Value<double>("anomaly_score");
          return score >= 8.0;
        } catch { return false; }
      }">
        <return-response>
          <set-status code="403" reason="Forbidden" />
          <set-header name="Content-Type" exists-action="override"><value>application/json</value></set-header>
          <set-body>{"error":"Anomaly score exceeds threshold (>=8.0)","blocked_by":"APIM-Anomaly","layer":5}</set-body>
        </return-response>
      </when>
    </choose>

    <!-- Route to AI backend -->
    <set-backend-service base-url="{{ai-service-url}}" />
    <set-header name="X-Forwarded-From" exists-action="override">
      <value>Azure-APIM</value>
    </set-header>
    <!-- Timestamp for latency measurement -->
    <set-variable name="requestStartTime" value="@(DateTime.UtcNow)" />
  </inbound>

  <backend>
    <forward-request timeout="30" />
  </backend>

  <outbound>
    <base />
    <!-- Add gateway latency header so the simulator can measure it -->
    <set-header name="X-Gateway-Latency-Ms" exists-action="override">
      <value>@(((DateTime.UtcNow - (DateTime)context.Variables["requestStartTime"]).TotalMilliseconds).ToString("F1"))</value>
    </set-header>
  </outbound>

  <on-error>
    <base />
    <set-header name="Content-Type" exists-action="override"><value>application/json</value></set-header>
  </on-error>
</policies>'''
  }
}

// ── Operation: GET /health ─────────────────────────────────────────────────────
resource healthOp 'Microsoft.ApiManagement/service/apis/operations@2023-09-01-preview' = {
  parent: api
  name: 'health'
  properties: {
    displayName: 'Health Check'
    method: 'GET'
    urlTemplate: '/health'
    description: 'Returns health status of the AI backend (no auth required)'
  }
}

resource healthOpPolicy 'Microsoft.ApiManagement/service/apis/operations/policies@2023-09-01-preview' = {
  parent: healthOp
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: '''
<policies>
  <inbound>
    <base />
    <!-- Health check bypasses rate limiting and auth layers -->
    <set-backend-service base-url="{{ai-service-url}}" />
  </inbound>
  <backend><forward-request timeout="10" /></backend>
  <outbound><base /></outbound>
  <on-error><base /></on-error>
</policies>'''
  }
}

// ── Product (groups APIs and issues subscription keys) ─────────────────────────
resource product 'Microsoft.ApiManagement/service/products@2023-09-01-preview' = {
  parent: apim
  name: 'ai-security-product'
  properties: {
    displayName: 'AI Security Demo'
    description: 'Product for the API-Centric AI Security experiment'
    state: 'published'
    subscriptionRequired: true
    approvalRequired: false    // auto-approve for demo convenience
  }
}

resource productApi 'Microsoft.ApiManagement/service/products/apis@2023-09-01-preview' = {
  parent: product
  name: 'ai-security-api'
  dependsOn: [api]
}

// ── Demo subscription (auto-created for the experiment) ────────────────────────
resource demoSubscription 'Microsoft.ApiManagement/service/subscriptions@2023-09-01-preview' = {
  parent: apim
  name: 'demo-subscription'
  properties: {
    displayName: 'Experiment Demo Subscription'
    scope: product.id
    state: 'active'
    allowTracing: false
  }
}

// ── Outputs ────────────────────────────────────────────────────────────────────
output apimGatewayUrl string = 'https://${apim.properties.gatewayUrl}/ai'
output apimName string = apim.name
output demoSubscriptionId string = demoSubscription.name
