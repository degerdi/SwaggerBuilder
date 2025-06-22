# 📚 Swagger Builder Documentation Guide

## 🎯 What is Swagger Builder?

The **Swagger Builder** is a powerful feature of the Enhanced Universal API Scanner that automatically creates professional API documentation for any web service. Whether you're a developer, project manager, or business analyst, this tool helps you understand and document APIs without manual work.

**What you get:**
- Complete API documentation in industry-standard OpenAPI format
- Ready-to-use documentation websites
- Client code generation for 40+ programming languages
- Professional-grade specifications for integration planning

## 🚀 Getting Started - Simple Examples

### Document Any Public API
```bash
# Generate documentation for any API
./api_scanner_cli.sh --swagger-output api-docs.yaml https://api.example.com
```

### With Authentication (Most Common)
```bash
# If the API requires a login token
./api_scanner_cli.sh --swagger-output docs.yaml \
  --auth-header "Bearer your-api-token" \
  https://api.example.com

# If the API uses API keys
./api_scanner_cli.sh --swagger-output docs.yaml \
  --api-key-header "X-API-Key:your-key" \
  https://api.example.com

# If you have username/password
./api_scanner_cli.sh --swagger-output docs.yaml \
  --username "your-username" \
  --password "your-password" \
  https://api.example.com
```

## 📋 Main Options

| Option | What it does | Example |
|--------|--------------|---------|
| `--swagger-output filename.yaml` | Saves documentation to a file | `--swagger-output my-api.yaml` |
| `--swagger-only` | Fast mode - documentation only | `--swagger-only` |
| `--deep-scan` | Thorough analysis (recommended) | `--deep-scan` |
| `--industry type` | Focus on specific business areas | `--industry healthcare` |
| `--max-coverage` | Most comprehensive analysis | `--max-coverage` |

## 🏢 Industry-Specific Documentation

The scanner understands different business domains and finds relevant endpoints automatically:

### Healthcare APIs
```bash
./api_scanner_cli.sh --industry healthcare \
  --swagger-output medical-api.yaml \
  --auth-header "Bearer your-token" \
  https://healthcare-api.com

# Automatically finds: patients, appointments, prescriptions, 
# lab results, billing, compliance endpoints
```

### Financial Services
```bash
./api_scanner_cli.sh --industry finance \
  --swagger-output banking-api.yaml \
  --username "api-user" \
  --password "secure-pass" \
  https://bank-api.com

# Automatically finds: accounts, transactions, payments, 
# investments, loans, regulatory reporting
```

### E-commerce/Retail
```bash
./api_scanner_cli.sh --industry ecommerce \
  --swagger-output shop-api.yaml \
  --api-key-header "X-Shop-Key:abc123" \
  https://store-api.com

# Automatically finds: products, inventory, orders, 
# customers, shipping, promotions
```

### Education
```bash
./api_scanner_cli.sh --industry education \
  --swagger-output school-api.yaml \
  --deep-scan \
  https://education-platform.com

# Automatically finds: students, courses, grades, 
# enrollment, schedules, assessments
```

## 🔧 Common Use Cases

### 1. **Understanding Third-Party APIs**
```bash
# Quickly understand what a vendor's API can do
./api_scanner_cli.sh --swagger-output vendor-api.yaml \
  --api-key-header "X-API-Key:your-key" \
  --deep-scan \
  https://vendor-api.com
```

### 2. **Creating Client Libraries**
```bash
# First, generate the documentation
./api_scanner_cli.sh --swagger-output api-spec.yaml https://api.example.com

# Then generate client code (requires OpenAPI Generator)
npx @openapitools/openapi-generator-cli generate \
  -i api-spec.yaml \
  -g python \
  -o ./python-client
```

### 3. **API Documentation Websites**
```bash
# Generate docs
./api_scanner_cli.sh --swagger-output api-docs.yaml https://api.example.com

# Create a documentation website
npx redoc-cli build api-docs.yaml --output index.html
```

### 4. **Integration Planning**
```bash
# Comprehensive analysis for integration projects
./api_scanner_cli.sh --max-coverage \
  --swagger-output complete-api-analysis.yaml \
  --auth-header "Bearer token" \
  --deep-scan \
  https://partner-api.com
```

## 📊 Discovery Modes

Choose the right level of analysis for your needs:

| Mode | Time | Best For |
|------|------|----------|
| **Quick** | 1-3 minutes | Initial exploration |
| **Standard** (default) | 2-5 minutes | Most common use |
| **Deep Scan** | 3-10 minutes | Thorough documentation |
| **Max Coverage** | 5-15 minutes | Complete analysis |

```bash
# Quick overview
./api_scanner_cli.sh --swagger-only https://api.example.com

# Thorough analysis (recommended)
./api_scanner_cli.sh --deep-scan --swagger-output docs.yaml https://api.example.com

# Complete analysis
./api_scanner_cli.sh --max-coverage --swagger-output complete.yaml https://api.example.com
```

## 📄 What You Get

The tool creates professional documentation including:

- **Complete API Reference** - All endpoints, parameters, and responses
- **Authentication Details** - How to connect and authenticate
- **Data Models** - Structure of requests and responses  
- **Code Examples** - Real examples from the API
- **Error Documentation** - Common errors and how to handle them
- **Interactive Documentation** - Browse and test the API

### Sample Output Structure
```yaml
openapi: 3.0.3
info:
  title: "Your API Documentation"
  description: "Auto-discovered API documentation"
  version: "1.0.0"
servers:
  - url: "https://api.example.com"
    description: "Production API Server"
paths:
  /users:
    get:
      summary: "Get all users"
      description: "Retrieve a list of all users"
      responses:
        '200':
          description: "Success"
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/User'
components:
  schemas:
    User:
      type: object
      properties:
        id:
          type: integer
          description: "User ID"
        name:
          type: string
          description: "User name"
        email:
          type: string
          format: email
          description: "User email address"
```

## 🛠️ Integration Examples

### Documenting Your Company's APIs
```bash
# Document internal APIs for team use
./api_scanner_cli.sh --swagger-output internal-api.yaml \
  --username "admin" \
  --password "company-password" \
  --deep-scan \
  https://internal-api.company.com
```

### Vendor API Analysis
```bash
# Understand what a vendor API offers
./api_scanner_cli.sh --swagger-output vendor-capabilities.yaml \
  --api-key-header "Authorization:Bearer vendor-token" \
  --max-coverage \
  https://vendor-api.com
```

### Multiple API Versions
```bash
# Document different versions
for version in v1 v2 v3; do
  ./api_scanner_cli.sh \
    --swagger-output "api-${version}-docs.yaml" \
    --auth-header "Bearer $API_TOKEN" \
    "https://api.example.com/${version}"
done
```

## 🔍 Advanced Features

### Framework Detection
The scanner automatically recognizes popular frameworks and finds their specific endpoints:

- **Spring Boot** - Finds actuator endpoints, admin interfaces
- **Django** - Discovers admin panel, REST framework endpoints  
- **WordPress** - Locates WP-JSON API, plugin endpoints
- **Node.js/Express** - Identifies common route patterns

### Smart Discovery
- **Content Analysis** - Reads JavaScript, HTML, and configuration files
- **Documentation Import** - Automatically imports existing Swagger/OpenAPI specs
- **Historical Analysis** - Checks archived versions for additional endpoints
- **Security Focus** - Identifies admin interfaces, debug endpoints, config files

## 💡 Tips for Best Results

### 1. Use Authentication
```bash
# APIs show more endpoints when authenticated
./api_scanner_cli.sh --swagger-output complete-docs.yaml \
  --auth-header "Bearer your-token" \
  --deep-scan \
  https://api.example.com
```

### 2. Industry Focus
```bash
# Get better results by specifying the business domain
./api_scanner_cli.sh --industry healthcare \
  --swagger-output medical-api.yaml \
  https://health-api.com
```

### 3. Custom Paths
```bash
# If you know specific paths, include them
./api_scanner_cli.sh --swagger-output docs.yaml \
  --paths "/api/v1,/admin,/health" \
  https://api.example.com
```

## 🔧 Troubleshooting

### Authentication Issues
```bash
# Try auto-detection if specific auth doesn't work
./api_scanner_cli.sh --swagger-output docs.yaml \
  --auth-method auto \
  --username "user" \
  --password "pass" \
  https://api.example.com
```

### Rate Limiting
```bash
# Slow down requests for rate-limited APIs
./api_scanner_cli.sh --swagger-output docs.yaml \
  --rate-limit 2.0 \
  --max-workers 1 \
  https://api.example.com
```

### Large APIs
```bash
# Optimize for speed on large APIs
./api_scanner_cli.sh --swagger-output docs.yaml \
  --swagger-only \
  --max-workers 10 \
  https://api.example.com
```

## 📈 Business Value

### For Development Teams
- **Faster Integration** - Understand APIs quickly without reading extensive documentation
- **Code Generation** - Automatically create client libraries in your preferred language
- **API Testing** - Generate test cases and validation scripts

### For Project Managers  
- **Integration Planning** - Understand scope and complexity of API integrations
- **Vendor Evaluation** - Compare API capabilities across different vendors
- **Documentation** - Create professional API documentation for stakeholders

### For Business Analysts
- **Capability Mapping** - Understand what business functions an API supports
- **Data Flow Analysis** - See how data moves between systems
- **Compliance Review** - Identify security and compliance-relevant endpoints

## 📞 Support

Need help or have questions? Email us at **degerdi@gmail.com**

We're here to help you get the most out of the Swagger Builder tool!

---

**Transform any API into professional documentation in minutes! 📚✨**
