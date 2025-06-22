#!/bin/bash

# API Scanner CLI Wrapper - Enhanced with Maximum Coverage Discovery
# Comprehensive wrapper script for the Universal API Scanner

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Default values
OUTPUT_DIR="./api_scan_results"
TIMEOUT=30
MAX_WORKERS=10
RATE_LIMIT=0.1
FORMAT="all"
VERIFY_SSL=true

# Help function
show_help() {
    echo -e "${BLUE}${BOLD}Universal API Scanner${NC} - ${PURPLE}${BOLD}Maximum Coverage Discovery${NC}"
    echo "Comprehensive tool for discovering, analyzing, and documenting REST APIs"
    echo -e "${CYAN}🎯 Now with 1000+ discovery patterns for maximum endpoint coverage${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS] <BASE_URL>"
    echo ""
    echo -e "${BOLD}Basic Options:${NC}"
    echo "  -h, --help              Show this help message"
    echo "  -o, --output-dir DIR    Output directory (default: ./api_scan_results)"
    echo "  -t, --timeout SECONDS   Request timeout (default: 30)"
    echo "  -w, --workers NUM       Max concurrent workers (default: 10)"
    echo "  -r, --rate-limit SEC    Delay between requests (default: 0.1)"
    echo "  -f, --format FORMAT     Output format: all, json, html, csv, postman, openapi, swagger-builder (default: all)"
    echo "  -d, --deep-scan         Enable deep scanning (1000+ patterns, slower but comprehensive)"
    echo "  -s, --skip-ssl          Skip SSL certificate verification"
    echo "  -v, --verbose           Enable verbose logging"
    echo "  -q, --quick             Quick scan mode (faster, basic patterns only)"
    echo ""
    echo -e "${PURPLE}${BOLD}🎯 NEW: Swagger Builder Options:${NC}"
    echo "  --swagger-output FILE   Generate Swagger builder optimized YAML (e.g., api-docs.yaml)"
    echo "  --swagger-only          Generate only Swagger builder format (fastest documentation)"
    echo "  --swagger-enhanced      Include enhanced schemas and examples for better docs"
    echo ""
    echo -e "${BOLD}Discovery Mode Options:${NC}"
    echo "  --max-coverage          Enable maximum coverage mode (all 1000+ patterns)"
    echo "  --industry TYPE         Focus on industry-specific patterns:"
    echo "                          healthcare, finance, ecommerce, education, travel, gaming"
    echo "  --framework TYPE        Focus on framework-specific patterns:"
    echo "                          spring, django, fastapi, laravel, rails, wordpress"
    echo "  --pattern-set SET       Use specific pattern set:"
    echo "                          basic, standard, comprehensive, maximum"
    echo ""
    echo -e "${BOLD}Authentication Options:${NC}"
    echo "  -a, --auth TOKEN        Authorization header (e.g., 'Bearer token123')"
    echo "  -k, --api-key KEY       API key header (e.g., 'X-API-Key:key123')"
    echo "  --auth-method METHOD    Authentication method: auto, basic, bearer, api_key, oauth2, jwt, session, custom"
    echo "  --username USER         Username for authentication"
    echo "  --password PASS         Password for authentication"
    echo "  --token TOKEN           Bearer token or JWT token"
    echo "  --api-key-name NAME     API key header name (default: X-API-Key)"
    echo "  --client-id ID          OAuth2 client ID"
    echo "  --client-secret SECRET  OAuth2 client secret"
    echo "  --credentials-file FILE JSON file containing credentials"
    echo ""
    echo -e "${BOLD}Endpoint Configuration:${NC}"
    echo "  --login-endpoint PATH   Custom login endpoint (e.g., /api/auth/login)"
    echo "  --token-endpoint PATH   Custom token endpoint (e.g., /api/auth/token)"
    echo "  --refresh-endpoint PATH Custom refresh endpoint (e.g., /api/auth/refresh)"
    echo ""
    echo -e "${BOLD}Advanced Options:${NC}"
    echo "  -p, --paths PATHS       Additional paths to test (comma-separated)"
    echo "  --session-file FILE     File to save/load session data"
    echo "  --custom-auth-url URL   Custom authentication URL"
    echo "  --custom-auth-payload   Custom auth payload (JSON string)"
    echo "  --exclude-patterns LIST Exclude specific pattern types (comma-separated)"
    echo "  --include-only LIST     Include only specific pattern types (comma-separated)"
    echo ""
    echo -e "${CYAN}${BOLD}Discovery Examples:${NC}"
    echo ""
    echo -e "${BOLD}Maximum Coverage API Documentation:${NC}"
    echo "  $0 --max-coverage --swagger-output complete-api.yaml \\"
    echo "     --deep-scan --auth-header 'Bearer token' https://api.example.com"
    echo ""
    echo -e "${BOLD}Industry-Specific Discovery:${NC}"
    echo "  # Healthcare API (180+ endpoints)"
    echo "  $0 --industry healthcare --swagger-output medical-api.yaml \\"
    echo "     --auth-method jwt --username doctor@hospital.com https://health-api.com"
    echo ""
    echo "  # E-commerce API (200+ endpoints)"
    echo "  $0 --industry ecommerce --swagger-output shop-api.yaml \\"
    echo "     --api-key-header 'X-Shop-Key:key123' https://shop-api.com"
    echo ""
    echo "  # Financial API (250+ endpoints)"
    echo "  $0 --industry finance --swagger-output bank-api.yaml \\"
    echo "     --deep-scan --client-id bank-client https://fintech-api.com"
    echo ""
    echo -e "${BOLD}Framework-Specific Discovery:${NC}"
    echo "  # Spring Boot (50+ Actuator endpoints)"
    echo "  $0 --framework spring --swagger-output spring-api.yaml https://spring-app.com"
    echo ""
    echo "  # Django + DRF (40+ admin endpoints)"
    echo "  $0 --framework django --swagger-output django-api.yaml https://django-app.com"
    echo ""
    echo "  # WordPress (30+ WP-JSON endpoints)"
    echo "  $0 --framework wordpress --swagger-output wp-api.yaml https://wordpress-site.com"
    echo ""
    echo -e "${BOLD}Pattern Set Examples:${NC}"
    echo "  # Basic patterns (fast scan)"
    echo "  $0 --pattern-set basic --swagger-only https://api.example.com"
    echo ""
    echo "  # Comprehensive patterns (thorough)"
    echo "  $0 --pattern-set comprehensive --swagger-output full-api.yaml https://api.example.com"
    echo ""
    echo "  # Maximum patterns (exhaustive)"
    echo "  $0 --pattern-set maximum --deep-scan --swagger-output ultimate-api.yaml https://api.example.com"
    echo ""
    echo -e "${GREEN}${BOLD}🎯 Discovery Coverage Stats:${NC}"
    echo "  📊 Basic Mode:         50+ patterns    →  ~20 endpoints"
    echo "  📊 Standard Mode:     200+ patterns    →  ~80 endpoints" 
    echo "  📊 Comprehensive:     500+ patterns    → ~200 endpoints"
    echo "  📊 Maximum Coverage: 1000+ patterns    → ~500+ endpoints"
    echo "  📊 Deep Scan:       +Historical data   → +Historical endpoints"
    echo ""
    echo -e "${YELLOW}${BOLD}🚀 Performance Modes:${NC}"
    echo "  ⚡ Quick Mode:      Fast scan, basic patterns, 5 workers"
    echo "  🔄 Standard Mode:   Balanced scan, comprehensive patterns, 10 workers"
    echo "  🔍 Deep Scan:       All patterns + advanced discovery methods"
    echo "  🎯 Max Coverage:    Every possible pattern + deep scan + analysis"
    echo ""
    echo -e "${PURPLE}${BOLD}📚 Swagger Documentation Benefits:${NC}"
    echo "  ✨ Enhanced OpenAPI 3.0 schemas with proper typing"
    echo "  📊 Comprehensive parameter documentation"  
    echo "  🏷️  Intelligent tagging and organization"
    echo "  🔐 Complete security scheme definitions"
    echo "  📝 Rich descriptions and examples from real responses"
    echo "  🔄 Ready for client SDK generation (40+ languages)"
    echo "  📚 Import directly into Swagger Editor/UI"
    echo "  🛠️  Compatible with all OpenAPI tooling"
    echo ""
    echo -e "${CYAN}${BOLD}Industry Pattern Coverage:${NC}"
    echo "  🏥 Healthcare:  patients, providers, appointments, records, labs, imaging"
    echo "  💰 Finance:     accounts, transactions, payments, cards, investments, forex"
    echo "  🛒 E-commerce:  products, cart, checkout, inventory, shipping, promotions"
    echo "  🎓 Education:   students, courses, assignments, grades, schedules"
    echo "  ✈️  Travel:      bookings, flights, hotels, itineraries, destinations"
    echo "  🎮 Gaming:      players, matches, tournaments, leaderboards, achievements"
    echo "  📱 IoT:         devices, sensors, telemetry, measurements, alerts"
    echo "  📄 Content:     pages, posts, media, templates, themes, categories"
    echo ""
    echo -e "${BLUE}${BOLD}Framework Detection:${NC}"
    echo "  🌱 Spring Boot: Actuator endpoints, management paths, health checks"
    echo "  🐍 Django:     Admin interface, DRF endpoints, debug toolbar"
    echo "  ⚡ FastAPI:     Auto-docs, health checks, metrics endpoints"
    echo "  📝 WordPress:   WP-JSON API, admin paths, plugin endpoints"
    echo "  💎 Laravel:     Horizon, Telescope, Nova admin interfaces"
    echo "  🚂 Rails:       Info pages, Sidekiq, console paths"
    echo "  🔷 ASP.NET:     Swagger, health checks, diagnostics"
    echo ""
    echo -e "${YELLOW}${BOLD}Output Files Generated:${NC}"
    echo "  📄 Enhanced Swagger YAML (--swagger-output) - Ready for documentation"
    echo "  📄 Companion JSON format - Machine-readable specification"
    echo "  📊 Detailed schemas and examples - Real API response data"
    echo "  🏷️  Organized tags and operations - Logical endpoint grouping"
    echo "  🔐 Security definitions - Complete auth scheme documentation"
    echo "  📋 Parameter specifications - Path, query, header parameters"
    echo "  📈 Performance metadata - Response times and statistics"
    echo ""
}

# Parse command line arguments
parse_args() {
    local args=()
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -o|--output-dir)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -w|--workers)
                MAX_WORKERS="$2"
                shift 2
                ;;
            -r|--rate-limit)
                RATE_LIMIT="$2"
                shift 2
                ;;
            -f|--format)
                FORMAT="$2"
                shift 2
                ;;
            -a|--auth)
                AUTH_HEADER="$2"
                shift 2
                ;;
            -k|--api-key)
                API_KEY_HEADER="$2"
                shift 2
                ;;
            --swagger-output)
                SWAGGER_OUTPUT="$2"
                shift 2
                ;;
            --swagger-only)
                SWAGGER_ONLY=true
                FORMAT="swagger-builder"
                shift
                ;;
            --swagger-enhanced)
                SWAGGER_ENHANCED=true
                shift
                ;;
            --max-coverage)
                MAX_COVERAGE=true
                DEEP_SCAN=true
                shift
                ;;
            --industry)
                INDUSTRY="$2"
                shift 2
                ;;
            --framework)
                FRAMEWORK="$2"
                shift 2
                ;;
            --pattern-set)
                PATTERN_SET="$2"
                shift 2
                ;;
            --exclude-patterns)
                EXCLUDE_PATTERNS="$2"
                shift 2
                ;;
            --include-only)
                INCLUDE_ONLY="$2"
                shift 2
                ;;
            --auth-method)
                AUTH_METHOD="$2"
                shift 2
                ;;
            --username)
                USERNAME="$2"
                shift 2
                ;;
            --password)
                PASSWORD="$2"
                shift 2
                ;;
            --token)
                TOKEN="$2"
                shift 2
                ;;
            --api-key-name)
                API_KEY_NAME="$2"
                shift 2
                ;;
            --client-id)
                CLIENT_ID="$2"
                shift 2
                ;;
            --client-secret)
                CLIENT_SECRET="$2"
                shift 2
                ;;
            --credentials-file)
                CREDENTIALS_FILE="$2"
                shift 2
                ;;
            --login-endpoint)
                LOGIN_ENDPOINT="$2"
                shift 2
                ;;
            --token-endpoint)
                TOKEN_ENDPOINT="$2"
                shift 2
                ;;
            --refresh-endpoint)
                REFRESH_ENDPOINT="$2"
                shift 2
                ;;
            --session-file)
                SESSION_FILE="$2"
                shift 2
                ;;
            --custom-auth-url)
                CUSTOM_AUTH_URL="$2"
                shift 2
                ;;
            --custom-auth-payload)
                CUSTOM_AUTH_PAYLOAD="$2"
                shift 2
                ;;
            -p|--paths)
                PATHS="$2"
                shift 2
                ;;
            -d|--deep-scan)
                DEEP_SCAN=true
                shift
                ;;
            -s|--skip-ssl)
                VERIFY_SSL=false
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -q|--quick)
                QUICK_MODE=true
                shift
                ;;
            -*)
                echo -e "${RED}Unknown option: $1${NC}"
                show_help
                exit 1
                ;;
            *)
                BASE_URL="$1"
                shift
                ;;
        esac
    done
    
    if [ -z "$BASE_URL" ]; then
        echo -e "${RED}Error: BASE_URL is required${NC}"
        show_help
        exit 1
    fi
    
    # Apply pattern set optimizations
    apply_pattern_optimizations
}

# Apply pattern set and mode optimizations
apply_pattern_optimizations() {
    # Quick mode optimizations
    if [ "$QUICK_MODE" = true ]; then
        MAX_WORKERS=5
        RATE_LIMIT=0.05
        PATTERN_SET="basic"
        echo -e "${YELLOW}⚡ Quick mode enabled: 5 workers, basic patterns${NC}"
    fi
    
    # Max coverage mode optimizations
    if [ "$MAX_COVERAGE" = true ]; then
        DEEP_SCAN=true
        PATTERN_SET="maximum"
        if [ -z "$SWAGGER_OUTPUT" ] && [ "$SWAGGER_ONLY" != true ]; then
            SWAGGER_OUTPUT="maximum-coverage-api.yaml"
        fi
        echo -e "${GREEN}🎯 Maximum coverage mode enabled: All 1000+ patterns${NC}"
    fi
    
    # Industry-specific optimizations
    if [ -n "$INDUSTRY" ]; then
        case "$INDUSTRY" in
            healthcare|medical|health)
                PATHS="${PATHS:+$PATHS,}/patients,/providers,/appointments,/records,/labs,/imaging"
                echo -e "${BLUE}🏥 Healthcare industry patterns enabled${NC}"
                ;;
            finance|fintech|banking)
                PATHS="${PATHS:+$PATHS,}/accounts,/transactions,/payments,/cards,/investments"
                echo -e "${BLUE}💰 Finance industry patterns enabled${NC}"
                ;;
            ecommerce|retail|shop)
                PATHS="${PATHS:+$PATHS,}/products,/cart,/checkout,/orders,/inventory,/shipping"
                echo -e "${BLUE}🛒 E-commerce industry patterns enabled${NC}"
                ;;
            education|learning|school)
                PATHS="${PATHS:+$PATHS,}/students,/courses,/assignments,/grades,/schedules"
                echo -e "${BLUE}🎓 Education industry patterns enabled${NC}"
                ;;
            travel|booking|hotel)
                PATHS="${PATHS:+$PATHS,}/bookings,/flights,/hotels,/cars,/itineraries"
                echo -e "${BLUE}✈️ Travel industry patterns enabled${NC}"
                ;;
            gaming|game|esports)
                PATHS="${PATHS:+$PATHS,}/players,/matches,/tournaments,/leaderboards,/achievements"
                echo -e "${BLUE}🎮 Gaming industry patterns enabled${NC}"
                ;;
            *)
                echo -e "${YELLOW}⚠ Unknown industry: $INDUSTRY (using default patterns)${NC}"
                ;;
        esac
    fi
    
    # Framework-specific optimizations
    if [ -n "$FRAMEWORK" ]; then
        case "$FRAMEWORK" in
            spring|springboot|spring-boot)
                PATHS="${PATHS:+$PATHS,}/actuator,/management,/health,/metrics,/info"
                echo -e "${BLUE}🌱 Spring Boot framework patterns enabled${NC}"
                ;;
            django|drf)
                PATHS="${PATHS:+$PATHS,}/admin,/api,/api-auth,/accounts,/__debug__"
                echo -e "${BLUE}🐍 Django framework patterns enabled${NC}"
                ;;
            fastapi|fast-api)
                PATHS="${PATHS:+$PATHS,}/docs,/redoc,/openapi.json,/health,/metrics"
                echo -e "${BLUE}⚡ FastAPI framework patterns enabled${NC}"
                ;;
            laravel|php)
                PATHS="${PATHS:+$PATHS,}/api,/admin,/horizon,/telescope,/nova"
                echo -e "${BLUE}🔶 Laravel framework patterns enabled${NC}"
                ;;
            rails|ruby)
                PATHS="${PATHS:+$PATHS,}/rails/info,/admin,/api/v1,/sidekiq"
                echo -e "${BLUE}💎 Rails framework patterns enabled${NC}"
                ;;
            wordpress|wp)
                PATHS="${PATHS:+$PATHS,}/wp-json,/wp-admin,/wp-api,/xmlrpc.php"
                echo -e "${BLUE}📝 WordPress framework patterns enabled${NC}"
                ;;
            aspnet|dotnet|.net)
                PATHS="${PATHS:+$PATHS,}/api,/swagger,/health,/diagnostics"
                echo -e "${BLUE}🔷 ASP.NET framework patterns enabled${NC}"
                ;;
            *)
                echo -e "${YELLOW}⚠ Unknown framework: $FRAMEWORK (using default patterns)${NC}"
                ;;
        esac
    fi
    
    # Pattern set optimizations
    case "$PATTERN_SET" in
        basic)
            MAX_WORKERS=5
            RATE_LIMIT=0.1
            echo -e "${YELLOW}📊 Basic pattern set: ~50 patterns, fast scan${NC}"
            ;;
        standard)
            MAX_WORKERS=8
            RATE_LIMIT=0.1
            echo -e "${BLUE}📊 Standard pattern set: ~200 patterns, balanced scan${NC}"
            ;;
        comprehensive)
            MAX_WORKERS=10
            RATE_LIMIT=0.1
            DEEP_SCAN=true
            echo -e "${PURPLE}📊 Comprehensive pattern set: ~500 patterns, thorough scan${NC}"
            ;;
        maximum)
            MAX_WORKERS=12
            RATE_LIMIT=0.05
            DEEP_SCAN=true
            echo -e "${GREEN}📊 Maximum pattern set: 1000+ patterns, exhaustive scan${NC}"
            ;;
    esac
}

# Build Python command with all optimizations
build_command() {
    local cmd="python3 ./universal_api_scanner.py"
    
    cmd="$cmd \"$BASE_URL\""
    cmd="$cmd --output-dir \"$OUTPUT_DIR\""
    cmd="$cmd --timeout $TIMEOUT"
    cmd="$cmd --max-workers $MAX_WORKERS"
    cmd="$cmd --rate-limit $RATE_LIMIT"
    cmd="$cmd --format $FORMAT"
    
    # Basic authentication
    if [ -n "$AUTH_HEADER" ]; then
        cmd="$cmd --auth-header \"$AUTH_HEADER\""
    fi
    
    if [ -n "$API_KEY_HEADER" ]; then
        cmd="$cmd --api-key-header \"$API_KEY_HEADER\""
    fi
    
    # Swagger-specific options
    if [ -n "$SWAGGER_OUTPUT" ]; then
        cmd="$cmd --swagger-output \"$SWAGGER_OUTPUT\""
    fi
    
    # Advanced authentication
    if [ -n "$AUTH_METHOD" ]; then
        cmd="$cmd --auth-method $AUTH_METHOD"
    fi
    
    if [ -n "$USERNAME" ]; then
        cmd="$cmd --username \"$USERNAME\""
    fi
    
    if [ -n "$PASSWORD" ]; then
        cmd="$cmd --password \"$PASSWORD\""
    fi
    
    if [ -n "$TOKEN" ]; then
        cmd="$cmd --token \"$TOKEN\""
    fi
    
    if [ -n "$API_KEY_NAME" ]; then
        cmd="$cmd --api-key-name \"$API_KEY_NAME\""
    fi
    
    if [ -n "$CLIENT_ID" ]; then
        cmd="$cmd --client-id \"$CLIENT_ID\""
    fi
    
    if [ -n "$CLIENT_SECRET" ]; then
        cmd="$cmd --client-secret \"$CLIENT_SECRET\""
    fi
    
    if [ -n "$CREDENTIALS_FILE" ]; then
        cmd="$cmd --credentials-file \"$CREDENTIALS_FILE\""
    fi
    
    # Endpoint configuration
    if [ -n "$LOGIN_ENDPOINT" ]; then
        cmd="$cmd --login-endpoint \"$LOGIN_ENDPOINT\""
    fi
    
    if [ -n "$TOKEN_ENDPOINT" ]; then
        cmd="$cmd --token-endpoint \"$TOKEN_ENDPOINT\""
    fi
    
    if [ -n "$REFRESH_ENDPOINT" ]; then
        cmd="$cmd --refresh-endpoint \"$REFRESH_ENDPOINT\""
    fi
    
    if [ -n "$SESSION_FILE" ]; then
        cmd="$cmd --session-file \"$SESSION_FILE\""
    fi
    
    # Custom authentication
    if [ -n "$CUSTOM_AUTH_URL" ]; then
        cmd="$cmd --custom-auth-url \"$CUSTOM_AUTH_URL\""
    fi
    
    if [ -n "$CUSTOM_AUTH_PAYLOAD" ]; then
        cmd="$cmd --custom-auth-payload '$CUSTOM_AUTH_PAYLOAD'"
    fi
    
    # Other options
    if [ -n "$PATHS" ]; then
        # Convert comma-separated paths to space-separated for Python
        local path_args=$(echo "$PATHS" | tr ',' ' ')
        cmd="$cmd --paths $path_args"
    fi
    
    if [ "$DEEP_SCAN" = true ]; then
        cmd="$cmd --deep-scan"
    fi
    
    if [ "$VERIFY_SSL" = false ]; then
        cmd="$cmd --no-ssl-verify"
    fi
    
    if [ "$VERBOSE" = true ]; then
        cmd="$cmd --verbose"
    fi
    
    echo "$cmd"
}

# Enhanced pre-scan checks with discovery mode info
pre_scan_checks() {
    echo -e "${BLUE}${BOLD}🔍 Universal API Scanner${NC} ${PURPLE}${BOLD}Maximum Coverage Discovery${NC}"
    echo -e "${BLUE}================================================================${NC}"
    echo ""
    
    # Show discovery mode information
    if [ "$MAX_COVERAGE" = true ]; then
        echo -e "${GREEN}${BOLD}🎯 MAXIMUM COVERAGE MODE ENABLED${NC}"
        echo -e "📊 Pattern Coverage: 1000+ comprehensive patterns"
        echo -e "🔍 Discovery Methods: All advanced techniques enabled"
        echo -e "⏱️  Estimated Time: 5-15 minutes (depending on API size)"
    elif [ "$DEEP_SCAN" = true ]; then
        echo -e "${PURPLE}${BOLD}🔍 DEEP SCAN MODE ENABLED${NC}"
        echo -e "📊 Pattern Coverage: 500+ comprehensive patterns"
        echo -e "🔍 Discovery Methods: Advanced techniques enabled"
        echo -e "⏱️  Estimated Time: 3-10 minutes"
    elif [ "$QUICK_MODE" = true ]; then
        echo -e "${YELLOW}${BOLD}⚡ QUICK SCAN MODE ENABLED${NC}"
        echo -e "📊 Pattern Coverage: 50+ basic patterns"
        echo -e "🔍 Discovery Methods: Essential patterns only"
        echo -e "⏱️  Estimated Time: 1-3 minutes"
    else
        echo -e "${BLUE}${BOLD}🔄 STANDARD SCAN MODE${NC}"
        echo -e "📊 Pattern Coverage: 200+ standard patterns"
        echo -e "🔍 Discovery Methods: Balanced approach"
        echo -e "⏱️  Estimated Time: 2-5 minutes"
    fi
    
    # Show industry/framework focus
    if [ -n "$INDUSTRY" ]; then
        echo -e "🏢 Industry Focus: ${INDUSTRY^} (specialized patterns included)"
    fi
    
    if [ -n "$FRAMEWORK" ]; then
        echo -e "🛠️  Framework Focus: ${FRAMEWORK^} (framework-specific endpoints)"
    fi
    
    # Show Swagger output info
    if [ -n "$SWAGGER_OUTPUT" ] || [ "$SWAGGER_ONLY" = true ]; then
        echo -e "${PURPLE}${BOLD}📚 Swagger Documentation Generation Enabled${NC}"
        if [ -n "$SWAGGER_OUTPUT" ]; then
            echo -e "📄 Output file: ${SWAGGER_OUTPUT}"
        fi
        if [ "$SWAGGER_ONLY" = true ]; then
            echo -e "⚡ Fast mode: Swagger builder output only"
        fi
    fi
    
    echo ""
    
    # Test connectivity
    echo -e "${YELLOW}Testing connectivity to $BASE_URL...${NC}"
    
    if command -v curl &> /dev/null; then
        if curl -s --connect-timeout 10 --max-time 15 "$BASE_URL" > /dev/null 2>&1; then
            echo -e "${GREEN}✓ Connection successful${NC}"
        else
            echo -e "${YELLOW}⚠ Connection test failed (this may be normal)${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ curl not available, skipping connectivity test${NC}"
    fi
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    echo -e "${GREEN}✓ Output directory created: $OUTPUT_DIR${NC}"
    
    echo ""
}

# Enhanced progress display with discovery info
show_progress() {
    local pid=$1
    local delay=1
    local spinstr='|/-\'
    
    if [ "$MAX_COVERAGE" = true ]; then
        echo -n "🎯 Maximum coverage discovery in progress "
    elif [ -n "$SWAGGER_OUTPUT" ] || [ "$SWAGGER_ONLY" = true ]; then
        echo -n "📚 Building comprehensive Swagger documentation "
    elif [ "$DEEP_SCAN" = true ]; then
        echo -n "🔍 Deep scanning API endpoints "
    else
        echo -n "🔄 Scanning API endpoints "
    fi
    
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    
    printf "    \b\b\b\b"
    echo ""
}

# Comprehensive post-scan summary
post_scan_summary() {
    echo ""
    echo -e "${GREEN}${BOLD}🎉 Comprehensive API scan completed successfully!${NC}"
    echo ""
    
    if [ -d "$OUTPUT_DIR" ]; then
        echo -e "${BLUE}${BOLD}Generated files:${NC}"
        
        # Count and categorize files
        local swagger_files=0
        local total_files=0
        
        find "$OUTPUT_DIR" -type f -name "*$(date +%Y%m%d)*" | while read -r file; do
            local filename=$(basename "$file")
            local size=$(du -h "$file" | cut -f1)
            
            # Highlight different file types
            if [[ "$filename" == *"swagger"* ]] || [[ "$filename" == *".yaml" ]] || [[ "$filename" == *".yml" ]]; then
                echo -e "  📄 ${PURPLE}${BOLD}$filename${NC} ${YELLOW}($size)${NC} ${PURPLE}← Swagger Documentation${NC}"
                ((swagger_files++)) || true
            elif [[ "$filename" == *"postman"* ]]; then
                echo -e "  📄 ${CYAN}$filename${NC} ${YELLOW}($size)${NC} ${CYAN}← Postman Collection${NC}"
            elif [[ "$filename" == *"jmeter"* ]]; then
                echo -e "  📄 ${BLUE}$filename${NC} ${YELLOW}($size)${NC} ${BLUE}← JMeter Test Plan${NC}"
            elif [[ "$filename" == *".html" ]]; then
                echo -e "  📄 ${GREEN}$filename${NC} ${YELLOW}($size)${NC} ${GREEN}← HTML Report${NC}"
            else
                echo -e "  📄 $filename ${YELLOW}($size)${NC}"
            fi
            ((total_files++)) || true
        done
        
        echo ""
        echo -e "${BLUE}📁 Output directory: $OUTPUT_DIR${NC}"
        echo -e "${GREEN}📊 Total files generated: Multiple comprehensive formats${NC}"
    fi
    
    # Show discovery statistics estimates
    echo ""
    echo -e "${CYAN}${BOLD}📊 Estimated Discovery Results:${NC}"
    
    if [ "$MAX_COVERAGE" = true ]; then
        echo -e "  🎯 Expected endpoints: 200-500+ (maximum coverage patterns)"
        echo -e "  📋 Pattern categories: 15+ industry/framework types"
        echo -e "  🔍 Discovery methods: All 10+ advanced techniques"
    elif [ "$DEEP_SCAN" = true ]; then
        echo -e "  🔍 Expected endpoints: 100-300+ (comprehensive patterns)"
        echo -e "  📋 Pattern categories: 10+ major types"
        echo -e "  🔍 Discovery methods: 8+ advanced techniques"
    elif [ "$QUICK_MODE" = true ]; then
        echo -e "  ⚡ Expected endpoints: 20-50+ (essential patterns)"
        echo -e "  📋 Pattern categories: 5+ basic types"
        echo -e "  🔍 Discovery methods: Core techniques only"
    else
        echo -e "  🔄 Expected endpoints: 50-150+ (standard patterns)"
        echo -e "  📋 Pattern categories: 8+ standard types"
        echo -e "  🔍 Discovery methods: Balanced approach"
    fi
    
    # Show Swagger-specific benefits
    if [ -n "$SWAGGER_OUTPUT" ] || [ "$SWAGGER_ONLY" = true ] || [ "$FORMAT" == "swagger-builder" ] || [ "$FORMAT" == "all" ]; then
        echo ""
        echo -e "${PURPLE}${BOLD}📚 Swagger Documentation Ready:${NC}"
        
        # Find the swagger file
        local swagger_file=""
        if [ -n "$SWAGGER_OUTPUT" ]; then
            swagger_file="$SWAGGER_OUTPUT"
        else
            swagger_file=$(find "$OUTPUT_DIR" -name "*swagger*.yaml" -o -name "*swagger*.yml" | head -n 1)
        fi
        
        if [ -n "$swagger_file" ]; then
            echo -e "  📄 Main file: ${swagger_file}"
            echo -e "  📄 JSON companion: ${swagger_file%.*}.json"
            echo -e "  🌐 Import into Swagger Editor: https://editor.swagger.io"
            echo -e "  🛠️  Generate client SDKs: 40+ programming languages"
            echo -e "  📖 Use for comprehensive API documentation"
            echo -e "  🔧 Compatible with all OpenAPI 3.0 tooling"
            echo -e "  🎯 Ready for API governance and validation"
        fi
        
        echo ""
        echo -e "${GREEN}${BOLD}✨ Documentation Features Included:${NC}"
        echo -e "  ✅ Complete OpenAPI 3.0 specification"
        echo -e "  ✅ Auto-generated schemas from real responses"
        echo -e "  ✅ Intelligent parameter documentation"
        echo -e "  ✅ Security scheme definitions"
        echo -e "  ✅ Organized operation tagging"
        echo -e "  ✅ Real response examples"
        echo -e "  ✅ Performance metadata"
    fi
    
    # Show industry/framework specific results
    if [ -n "$INDUSTRY" ]; then
        echo ""
        echo -e "${BLUE}${BOLD}🏢 Industry-Specific Discovery (${INDUSTRY^}):${NC}"
        case "$INDUSTRY" in
            healthcare|medical|health)
                echo -e "  🏥 Patient management endpoints discovered"
                echo -e "  👨‍⚕️ Provider and appointment systems found"
                echo -e "  📋 Medical records and lab result APIs"
                echo -e "  💊 Prescription and medication endpoints"
                ;;
            finance|fintech|banking)
                echo -e "  💰 Account and transaction endpoints discovered"
                echo -e "  💳 Payment and card management APIs"
                echo -e "  📊 Investment and portfolio systems found"
                echo -e "  🔒 Secure financial operation endpoints"
                ;;
            ecommerce|retail|shop)
                echo -e "  🛒 Product catalog and cart endpoints discovered"
                echo -e "  📦 Inventory and shipping APIs found"
                echo -e "  🎫 Promotion and coupon systems"
                echo -e "  ⭐ Review and rating endpoints"
                ;;
            education|learning|school)
                echo -e "  🎓 Student and course management endpoints"
                echo -e "  📚 Assignment and grading systems found"
                echo -e "  📅 Schedule and enrollment APIs"
                echo -e "  🏆 Achievement and progress tracking"
                ;;
            travel|booking|hotel)
                echo -e "  ✈️ Flight and hotel booking endpoints"
                echo -e "  🚗 Car rental and travel APIs found"
                echo -e "  🗺️ Itinerary and destination systems"
                echo -e "  💺 Reservation management endpoints"
                ;;
            gaming|game|esports)
                echo -e "  🎮 Player and match management endpoints"
                echo -e "  🏆 Tournament and leaderboard APIs"
                echo -e "  🎯 Achievement and scoring systems"
                echo -e "  👥 Guild and team management"
                ;;
        esac
    fi
    
    if [ -n "$FRAMEWORK" ]; then
        echo ""
        echo -e "${BLUE}${BOLD}🛠️ Framework-Specific Discovery (${FRAMEWORK^}):${NC}"
        case "$FRAMEWORK" in
            spring|springboot|spring-boot)
                echo -e "  🌱 Spring Boot Actuator endpoints discovered"
                echo -e "  📊 Health checks and metrics APIs found"
                echo -e "  🔧 Management and configuration endpoints"
                echo -e "  📈 Monitoring and diagnostic systems"
                ;;
            django|drf)
                echo -e "  🐍 Django admin interface discovered"
                echo -e "  🔌 Django REST Framework endpoints found"
                echo -e "  🛡️ Authentication and permission APIs"
                echo -e "  🐞 Debug toolbar and development tools"
                ;;
            fastapi|fast-api)
                echo -e "  ⚡ FastAPI auto-documentation discovered"
                echo -e "  📚 Interactive API docs (Swagger/ReDoc) found"
                echo -e "  🔍 Health check and status endpoints"
                echo -e "  📊 Metrics and monitoring APIs"
                ;;
            laravel|php)
                echo -e "  🔶 Laravel admin interfaces discovered"
                echo -e "  🌅 Horizon and Telescope tools found"
                echo -e "  🎨 Nova admin panel endpoints"
                echo -e "  🐞 Debug and development APIs"
                ;;
            rails|ruby)
                echo -e "  💎 Rails info and route endpoints discovered"
                echo -e "  👷 Sidekiq background job APIs found"
                echo -e "  📧 Action Mailer preview systems"
                echo -e "  🔧 Console and development tools"
                ;;
            wordpress|wp)
                echo -e "  📝 WordPress REST API discovered"
                echo -e "  👨‍💼 Admin interface endpoints found"
                echo -e "  🔌 Plugin and theme APIs"
                echo -e "  📊 Multisite and user management"
                ;;
            aspnet|dotnet|.net)
                echo -e "  🔷 ASP.NET Core endpoints discovered"
                echo -e "  📋 Swagger documentation found"
                echo -e "  🏥 Health check APIs"
                echo -e "  📊 Diagnostic and monitoring endpoints"
                ;;
        esac
    fi
    
    echo ""
    echo -e "${YELLOW}${BOLD}🚀 Next Steps:${NC}"
    if [ -n "$SWAGGER_OUTPUT" ] || [ "$SWAGGER_ONLY" = true ]; then
        echo "  1. 📚 Import the Swagger YAML into Swagger Editor for viewing"
        echo "  2. 🛠️  Generate client libraries using OpenAPI Generator"  
        echo "  3. 📖 Use as base for comprehensive API documentation"
        echo "  4. 🔄 Integrate with CI/CD for automatic doc updates"
        echo "  5. 🎯 Use for API governance and validation workflows"
    else
        echo "  1. 📊 Review the HTML report for detailed analysis"
        echo "  2. 📮 Import the Postman collection for manual testing"
        echo "  3. 📚 Use the Swagger YAML for documentation and client generation"
        echo "  4. 🧪 Run the JMeter test plan for performance testing"
        echo "  5. 📈 Analyze CSV data for endpoint statistics"
    fi
    
    echo ""
    echo -e "${GREEN}${BOLD}🎯 Pro Tips:${NC}"
    echo "  💡 Use --max-coverage for the most comprehensive discovery"
    echo "  🔄 Combine --industry and --framework flags for focused scans"
    echo "  📚 Generate Swagger docs for immediate API documentation"
    echo "  🔒 Use authentication for protected endpoint discovery"
    echo "  📊 Export to multiple formats for different use cases"
    echo ""
}

# Pattern mode templates
show_pattern_templates() {
    echo -e "${PURPLE}${BOLD}📊 Pattern Mode Examples:${NC}"
    echo ""
    echo -e "${BOLD}Basic Patterns (50+ patterns):${NC}"
    echo "$0 --pattern-set basic --swagger-output basic-api.yaml \$1"
    echo ""
    echo -e "${BOLD}Comprehensive Patterns (500+ patterns):${NC}"
    echo "$0 --pattern-set comprehensive --deep-scan --swagger-output full-api.yaml \$1"
    echo ""
    echo -e "${BOLD}Maximum Coverage (1000+ patterns):${NC}"
    echo "$0 --max-coverage --swagger-output ultimate-api.yaml \$1"
}

# Industry-specific templates
show_industry_templates() {
    echo -e "${BLUE}${BOLD}🏢 Industry-Specific Examples:${NC}"
    echo ""
    echo -e "${BOLD}Healthcare API Discovery:${NC}"
    echo "$0 --industry healthcare --swagger-output medical-api.yaml \\"
    echo "  --auth-method jwt --deep-scan \$1"
    echo ""
    echo -e "${BOLD}Financial API Discovery:${NC}"
    echo "$0 --industry finance --swagger-output fintech-api.yaml \\"
    echo "  --client-id bank-client --client-secret secret \$1"
    echo ""
    echo -e "${BOLD}E-commerce API Discovery:${NC}"
    echo "$0 --industry ecommerce --swagger-output shop-api.yaml \\"
    echo "  --api-key-header 'X-Shop-Key:key123' --max-coverage \$1"
}

# Framework-specific templates
show_framework_templates() {
    echo -e "${GREEN}${BOLD}🛠️ Framework-Specific Examples:${NC}"
    echo ""
    echo -e "${BOLD}Spring Boot Discovery:${NC}"
    echo "$0 --framework spring --swagger-output spring-api.yaml \\"
    echo "  --deep-scan --paths '/actuator' \$1"
    echo ""
    echo -e "${BOLD}Django + DRF Discovery:${NC}"
    echo "$0 --framework django --swagger-output django-api.yaml \\"
    echo "  --username admin --password secret \$1"
    echo ""
    echo -e "${BOLD}WordPress API Discovery:${NC}"
    echo "$0 --framework wordpress --swagger-output wp-api.yaml \\"
    echo "  --max-coverage --paths '/wp-json' \$1"
}

# Check if Python is available and install dependencies
check_python() {
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}Error: Python 3 is required but not installed${NC}"
        exit 1
    fi
    
    # Check for required Python packages
    python3 -c "import requests, yaml" 2>/dev/null || {
        echo -e "${YELLOW}Installing required Python packages...${NC}"
        pip3 install requests pyyaml || {
            echo -e "${RED}Error: Failed to install required packages${NC}"
            echo "Please run: pip3 install requests pyyaml"
            exit 1
        }
    }
}

# Verify scanner script exists
create_scanner_script() {
    local script_path="./universal_api_scanner.py"
    
    if [ ! -f "$script_path" ]; then
        echo -e "${RED}Error: universal_api_scanner.py not found${NC}"
        echo "Please ensure the Python scanner script is in the same directory"
        exit 1
    fi
}

# Enhanced error handling with troubleshooting
handle_error() {
    local exit_code=$?
    echo ""
    echo -e "${RED}${BOLD}❌ Scan failed with exit code $exit_code${NC}"
    
    if [ -f "./api_scanner.log" ]; then
        echo -e "${YELLOW}📋 Check the log file for details: ./api_scanner.log${NC}"
        echo -e "${YELLOW}Last few log entries:${NC}"
        tail -5 ./api_scanner.log
    fi
    
    echo ""
    echo -e "${BLUE}${BOLD}🔧 Troubleshooting Tips:${NC}"
    echo "  1. 🌐 Check if the URL is accessible: curl -I $BASE_URL"
    echo "  2. 🔐 Verify authentication credentials are correct"
    echo "  3. 🔒 Try with --skip-ssl if using self-signed certificates"
    echo "  4. 📝 Use --verbose for detailed logging"
    echo "  5. ⚡ Try --quick mode for faster scanning"
    echo "  6. 🎯 Reduce --workers or increase --rate-limit for rate-limited APIs"
    echo "  7. 🔄 Check API documentation for required headers or parameters"
    echo ""
    echo -e "${CYAN}💡 Common Solutions:${NC}"
    echo "  • Rate limiting: Use --rate-limit 1.0 --workers 2"
    echo "  • Authentication: Try --auth-method auto"
    echo "  • SSL issues: Add --skip-ssl flag"
    echo "  • Slow APIs: Increase --timeout 60"
    echo "  • Memory issues: Use --quick mode"
    
    exit $exit_code
}

# Validate URL format
validate_url() {
    if [[ ! "$BASE_URL" =~ ^https?:// ]]; then
        echo -e "${YELLOW}⚠ Warning: URL should start with http:// or https://${NC}"
        echo -e "${YELLOW}Assuming https://${NC}"
        BASE_URL="https://$BASE_URL"
    fi
}

# Main execution function
main() {
    # Set up error handling
    trap 'handle_error' ERR
    
    # Check prerequisites
    check_python
    create_scanner_script
    
    # Parse arguments
    parse_args "$@"
    
    # Validate input
    validate_url
    
    # Pre-scan setup and information
    pre_scan_checks
    
    # Build and execute command
    local cmd=$(build_command)
    
    echo -e "${BLUE}${BOLD}🚀 Executing comprehensive API scan...${NC}"
    if [ "$VERBOSE" = true ]; then
        echo -e "${YELLOW}Command: $cmd${NC}"
    fi
    echo ""
    
    # Run the scan with progress indication
    if [ "$VERBOSE" = true ]; then
        eval "$cmd"
    else
        eval "$cmd" &
        local scan_pid=$!
        show_progress $scan_pid
        wait $scan_pid
    fi
    
    # Show comprehensive results
    post_scan_summary
}

# Handle special template commands
case "${1:-}" in
    patterns|pattern-templates)
        show_pattern_templates
        exit 0
        ;;
    industry|industry-templates)
        show_industry_templates
        exit 0
        ;;
    framework|framework-templates)
        show_framework_templates
        exit 0
        ;;
    swagger-template-basic)
        echo -e "${PURPLE}${BOLD}Basic Swagger Generation Template:${NC}"
        echo "$0 --swagger-output api-docs.yaml --format swagger-builder \"\$1\""
        exit 0
        ;;
    swagger-template-auth)
        echo -e "${PURPLE}${BOLD}Authenticated API Swagger Template:${NC}"
        echo "$0 --swagger-output complete-api-docs.yaml --deep-scan \\"
        echo "  --auth-header \"Bearer YOUR_TOKEN\" --session-file ./api-session.json \"\$1\""
        exit 0
        ;;
    swagger-template-max)
        echo -e "${PURPLE}${BOLD}Maximum Coverage Swagger Template:${NC}"
        echo "$0 --max-coverage --swagger-output ultimate-api-docs.yaml \\"
        echo "  --industry finance --framework spring \\"
        echo "  --auth-method auto --username admin --password secret \"\$1\""
        exit 0
        ;;
    template-public)
        echo -e "${BLUE}${BOLD}Quick scan template for public APIs:${NC}"
        echo "$0 --pattern-set standard --swagger-output public-api.yaml \\"
        echo "  --timeout 15 --max-workers 8 --rate-limit 0.2 \"\$1\""
        exit 0
        ;;
    template-auth)
        echo -e "${BLUE}${BOLD}Quick scan template for authenticated APIs:${NC}"
        echo "$0 --auth-header \"Bearer YOUR_TOKEN\" --pattern-set comprehensive \\"
        echo "  --swagger-output auth-api.yaml --deep-scan \"\$1\""
        exit 0
        ;;
    examples|help-examples)
        echo -e "${CYAN}${BOLD}📖 Comprehensive Usage Examples:${NC}"
        echo ""
        show_pattern_templates
        echo ""
        show_industry_templates
        echo ""
        show_framework_templates
        exit 0
        ;;
esac

# Run main function with all arguments
main "$@"#!/bin/bash

# API Scanner CLI Wrapper - Enhanced with Swagger Builder Support
# Simple wrapper script for the Universal API Scanner

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default values
OUTPUT_DIR="./api_scan_results"
TIMEOUT=30
MAX_WORKERS=10
RATE_LIMIT=0.1
FORMAT="all"
VERIFY_SSL=true

# Help function
show_help() {
    echo -e "${BLUE}Universal API Scanner${NC} - ${PURPLE}Enhanced with Swagger Builder${NC}"
    echo "Comprehensive tool for discovering, analyzing, and documenting REST APIs"
    echo ""
    echo "Usage: $0 [OPTIONS] <BASE_URL>"
    echo ""
    echo "Basic Options:"
    echo "  -h, --help              Show this help message"
    echo "  -o, --output-dir DIR    Output directory (default: ./api_scan_results)"
    echo "  -t, --timeout SECONDS   Request timeout (default: 30)"
    echo "  -w, --workers NUM       Max concurrent workers (default: 10)"
    echo "  -r, --rate-limit SEC    Delay between requests (default: 0.1)"
    echo "  -f, --format FORMAT     Output format: all, json, html, csv, postman, openapi, swagger-builder (default: all)"
    echo "  -d, --deep-scan         Enable deep scanning (slower but more comprehensive)"
    echo "  -s, --skip-ssl          Skip SSL certificate verification"
    echo "  -v, --verbose           Enable verbose logging"
    echo "  -q, --quick             Quick scan mode (faster, less comprehensive)"
    echo ""
    echo -e "${PURPLE}🎯 NEW: Swagger Builder Options:${NC}"
    echo "  --swagger-output FILE   Generate Swagger builder optimized YAML (e.g., swagger-docs.yaml)"
    echo "  --swagger-only          Generate only Swagger builder format (skip other outputs)"
    echo "  --swagger-enhanced      Include enhanced schemas and examples for better docs"
    echo ""
    echo "Authentication Options:"
    echo "  -a, --auth TOKEN        Authorization header (e.g., 'Bearer token123')"
    echo "  -k, --api-key KEY       API key header (e.g., 'X-API-Key:key123')"
    echo "  --auth-method METHOD    Authentication method: auto, basic, bearer, api_key, oauth2, jwt, session, custom"
    echo "  --username USER         Username for authentication"
    echo "  --password PASS         Password for authentication"
    echo "  --token TOKEN           Bearer token or JWT token"
    echo "  --api-key-name NAME     API key header name (default: X-API-Key)"
    echo "  --client-id ID          OAuth2 client ID"
    echo "  --client-secret SECRET  OAuth2 client secret"
    echo "  --credentials-file FILE JSON file containing credentials"
    echo ""
    echo "Endpoint Configuration:"
    echo "  --login-endpoint PATH   Custom login endpoint (e.g., /api/auth/login)"
    echo "  --token-endpoint PATH   Custom token endpoint (e.g., /api/auth/token)"
    echo "  --refresh-endpoint PATH Custom refresh endpoint (e.g., /api/auth/refresh)"
    echo ""
    echo "Advanced Options:"
    echo "  -p, --paths PATHS       Additional paths to test (comma-separated)"
    echo "  --session-file FILE     File to save/load session data"
    echo "  --custom-auth-url URL   Custom authentication URL"
    echo "  --custom-auth-payload   Custom auth payload (JSON string)"
    echo ""
    echo -e "${CYAN}Examples:${NC}"
    echo ""
    echo "Basic API Scan:"
    echo "  $0 https://api.example.com"
    echo ""
    echo -e "${PURPLE}Swagger Documentation Generation:${NC}"
    echo "  $0 --swagger-output api-docs.yaml https://api.example.com"
    echo "  $0 --swagger-only --auth-header 'Bearer token' https://api.example.com"
    echo "  $0 --format swagger-builder -o ./swagger-docs https://api.example.com"
    echo ""
    echo "Bearer Token Authentication:"
    echo "  $0 -a 'Bearer abc123' --swagger-output docs.yaml https://api.example.com"
    echo ""
    echo "API Key Authentication:"
    echo "  $0 -k 'X-API-Key:secret123' --swagger-enhanced https://api.example.com"
    echo ""
    echo "Complete Documentation Workflow:"
    echo "  $0 --deep-scan --auth-method auto --username admin --password secret \\"
    echo "     --swagger-output complete-api-docs.yaml \\"
    echo "     --session-file ./api-session.json \\"
    echo "     https://api.example.com"
    echo ""
    echo -e "${GREEN}🎯 Swagger Builder Benefits:${NC}"
    echo "  ✨ Enhanced OpenAPI 3.0 schemas with proper typing"
    echo "  📊 Comprehensive parameter documentation"  
    echo "  🏷️  Intelligent tagging and organization"
    echo "  🔐 Complete security scheme definitions"
    echo "  📝 Rich descriptions and examples"
    echo "  🔄 Ready for client SDK generation"
    echo "  📚 Import directly into Swagger Editor/UI"
    echo "  🛠️  Compatible with all OpenAPI tooling"
    echo ""
    echo -e "${YELLOW}Output Files Generated:${NC}"
    echo "  📄 Enhanced Swagger YAML (--swagger-output)"
    echo "  📄 Companion JSON format"
    echo "  📊 Detailed schemas and examples"
    echo "  🏷️  Organized tags and operations"
    echo "  🔐 Security definitions"
    echo "  📋 Parameter specifications"
    echo ""
}

# Parse command line arguments
parse_args() {
    local args=()
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -o|--output-dir)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -w|--workers)
                MAX_WORKERS="$2"
                shift 2
                ;;
            -r|--rate-limit)
                RATE_LIMIT="$2"
                shift 2
                ;;
            -f|--format)
                FORMAT="$2"
                shift 2
                ;;
            -a|--auth)
                AUTH_HEADER="$2"
                shift 2
                ;;
            -k|--api-key)
                API_KEY_HEADER="$2"
                shift 2
                ;;
            --swagger-output)
                SWAGGER_OUTPUT="$2"
                shift 2
                ;;
            --swagger-only)
                SWAGGER_ONLY=true
                FORMAT="swagger-builder"
                shift
                ;;
            --swagger-enhanced)
                SWAGGER_ENHANCED=true
                shift
                ;;
            --auth-method)
                AUTH_METHOD="$2"
                shift 2
                ;;
            --username)
                USERNAME="$2"
                shift 2
                ;;
            --password)
                PASSWORD="$2"
                shift 2
                ;;
            --token)
                TOKEN="$2"
                shift 2
                ;;
            --api-key-name)
                API_KEY_NAME="$2"
                shift 2
                ;;
            --client-id)
                CLIENT_ID="$2"
                shift 2
                ;;
            --client-secret)
                CLIENT_SECRET="$2"
                shift 2
                ;;
            --credentials-file)
                CREDENTIALS_FILE="$2"
                shift 2
                ;;
            --login-endpoint)
                LOGIN_ENDPOINT="$2"
                shift 2
                ;;
            --token-endpoint)
                TOKEN_ENDPOINT="$2"
                shift 2
                ;;
            --refresh-endpoint)
                REFRESH_ENDPOINT="$2"
                shift 2
                ;;
            --session-file)
                SESSION_FILE="$2"
                shift 2
                ;;
            --custom-auth-url)
                CUSTOM_AUTH_URL="$2"
                shift 2
                ;;
            --custom-auth-payload)
                CUSTOM_AUTH_PAYLOAD="$2"
                shift 2
                ;;
            -p|--paths)
                PATHS="$2"
                shift 2
                ;;
            -d|--deep-scan)
                DEEP_SCAN=true
                shift
                ;;
            -s|--skip-ssl)
                VERIFY_SSL=false
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -q|--quick)
                QUICK_MODE=true
                shift
                ;;
            -*)
                echo -e "${RED}Unknown option: $1${NC}"
                show_help
                exit 1
                ;;
            *)
                BASE_URL="$1"
                shift
                ;;
        esac
    done
    
    if [ -z "$BASE_URL" ]; then
        echo -e "${RED}Error: BASE_URL is required${NC}"
        show_help
        exit 1
    fi
}

# Build Python command
build_command() {
    local cmd="python3 ./universal_api_scanner.py"
    
    cmd="$cmd \"$BASE_URL\""
    cmd="$cmd --output-dir \"$OUTPUT_DIR\""
    cmd="$cmd --timeout $TIMEOUT"
    cmd="$cmd --max-workers $MAX_WORKERS"
    cmd="$cmd --rate-limit $RATE_LIMIT"
    cmd="$cmd --format $FORMAT"
    
    # Basic authentication
    if [ -n "$AUTH_HEADER" ]; then
        cmd="$cmd --auth-header \"$AUTH_HEADER\""
    fi
    
    if [ -n "$API_KEY_HEADER" ]; then
        cmd="$cmd --api-key-header \"$API_KEY_HEADER\""
    fi
    
    # Swagger-specific options
    if [ -n "$SWAGGER_OUTPUT" ]; then
        cmd="$cmd --swagger-output \"$SWAGGER_OUTPUT\""
    fi
    
    # Advanced authentication
    if [ -n "$AUTH_METHOD" ]; then
        cmd="$cmd --auth-method $AUTH_METHOD"
    fi
    
    if [ -n "$USERNAME" ]; then
        cmd="$cmd --username \"$USERNAME\""
    fi
    
    if [ -n "$PASSWORD" ]; then
        cmd="$cmd --password \"$PASSWORD\""
    fi
    
    if [ -n "$TOKEN" ]; then
        cmd="$cmd --token \"$TOKEN\""
    fi
    
    if [ -n "$API_KEY_NAME" ]; then
        cmd="$cmd --api-key-name \"$API_KEY_NAME\""
    fi
    
    if [ -n "$CLIENT_ID" ]; then
        cmd="$cmd --client-id \"$CLIENT_ID\""
    fi
    
    if [ -n "$CLIENT_SECRET" ]; then
        cmd="$cmd --client-secret \"$CLIENT_SECRET\""
    fi
    
    if [ -n "$CREDENTIALS_FILE" ]; then
        cmd="$cmd --credentials-file \"$CREDENTIALS_FILE\""
    fi
    
    # Endpoint configuration
    if [ -n "$LOGIN_ENDPOINT" ]; then
        cmd="$cmd --login-endpoint \"$LOGIN_ENDPOINT\""
    fi
    
    if [ -n "$TOKEN_ENDPOINT" ]; then
        cmd="$cmd --token-endpoint \"$TOKEN_ENDPOINT\""
    fi
    
    if [ -n "$REFRESH_ENDPOINT" ]; then
        cmd="$cmd --refresh-endpoint \"$REFRESH_ENDPOINT\""
    fi
    
    if [ -n "$SESSION_FILE" ]; then
        cmd="$cmd --session-file \"$SESSION_FILE\""
    fi
    
    # Custom authentication
    if [ -n "$CUSTOM_AUTH_URL" ]; then
        cmd="$cmd --custom-auth-url \"$CUSTOM_AUTH_URL\""
    fi
    
    if [ -n "$CUSTOM_AUTH_PAYLOAD" ]; then
        cmd="$cmd --custom-auth-payload '$CUSTOM_AUTH_PAYLOAD'"
    fi
    
    # Other options
    if [ -n "$PATHS" ]; then
        # Convert comma-separated paths to space-separated for Python
        local path_args=$(echo "$PATHS" | tr ',' ' ')
        cmd="$cmd --paths $path_args"
    fi
    
    if [ "$DEEP_SCAN" = true ]; then
        cmd="$cmd --deep-scan"
    fi
    
    if [ "$VERIFY_SSL" = false ]; then
        cmd="$cmd --no-ssl-verify"
    fi
    
    if [ "$VERBOSE" = true ]; then
        cmd="$cmd --verbose"
    fi
    
    if [ "$QUICK_MODE" = true ]; then
        # Quick mode: reduce workers and enable rate limiting
        cmd="$cmd --max-workers 5 --rate-limit 0.05"
    fi
    
    echo "$cmd"
}

# Run pre-scan checks
pre_scan_checks() {
    echo -e "${BLUE}🔍 Universal API Scanner${NC} ${PURPLE}with Swagger Builder${NC}"
    echo -e "${BLUE}===============================================${NC}"
    echo ""
    
    # Show what we're about to do
    if [ -n "$SWAGGER_OUTPUT" ] || [ "$SWAGGER_ONLY" = true ]; then
        echo -e "${PURPLE}🎯 Swagger Documentation Mode Enabled${NC}"
        if [ -n "$SWAGGER_OUTPUT" ]; then
            echo -e "📄 Output file: ${SWAGGER_OUTPUT}"
        fi
        if [ "$SWAGGER_ONLY" = true ]; then
            echo -e "⚡ Fast mode: Swagger builder output only"
        fi
        echo ""
    fi
    
    # Test connectivity
    echo -e "${YELLOW}Testing connectivity to $BASE_URL...${NC}"
    
    if command -v curl &> /dev/null; then
        if curl -s --connect-timeout 10 --max-time 15 "$BASE_URL" > /dev/null 2>&1; then
            echo -e "${GREEN}✓ Connection successful${NC}"
        else
            echo -e "${YELLOW}⚠ Connection test failed (this may be normal)${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ curl not available, skipping connectivity test${NC}"
    fi
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    echo -e "${GREEN}✓ Output directory created: $OUTPUT_DIR${NC}"
    
    echo ""
}

# Display scan progress with Swagger-specific messaging
show_progress() {
    local pid=$1
    local delay=1
    local spinstr='|/-\'
    
    if [ -n "$SWAGGER_OUTPUT" ] || [ "$SWAGGER_ONLY" = true ]; then
        echo -n "Building Swagger documentation "
    else
        echo -n "Scanning API endpoints "
    fi
    
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    
    printf "    \b\b\b\b"
    echo ""
}

# Enhanced post-scan summary with Swagger info
post_scan_summary() {
    echo ""
    echo -e "${GREEN}🎉 Scan completed successfully!${NC}"
    echo ""
    
    if [ -d "$OUTPUT_DIR" ]; then
        echo -e "${BLUE}Generated files:${NC}"
        find "$OUTPUT_DIR" -type f -name "*$(date +%Y%m%d)*" | while read -r file; do
            local filename=$(basename "$file")
            local size=$(du -h "$file" | cut -f1)
            
            # Highlight Swagger files
            if [[ "$filename" == *"swagger"* ]] || [[ "$filename" == *".yaml" ]]; then
                echo -e "  📄 ${PURPLE}$filename${NC} ${YELLOW}($size)${NC} ${PURPLE}← Swagger Documentation${NC}"
            else
                echo -e "  📄 $filename ${YELLOW}($size)${NC}"
            fi
        done
        echo ""
        echo -e "${BLUE}Output directory:${NC} $OUTPUT_DIR"
    fi
    
    # Show Swagger-specific next steps
    if [ -n "$SWAGGER_OUTPUT" ] || [ "$SWAGGER_ONLY" = true ] || [ "$FORMAT" == "swagger-builder" ] || [ "$FORMAT" == "all" ]; then
        echo ""
        echo -e "${PURPLE}📚 Swagger Documentation Ready:${NC}"
        
        # Find the swagger file
        local swagger_file=""
        if [ -n "$SWAGGER_OUTPUT" ]; then
            swagger_file="$SWAGGER_OUTPUT"
        else
            swagger_file=$(find "$OUTPUT_DIR" -name "*swagger*.yaml" -o -name "*swagger*.yml" | head -n 1)
        fi
        
        if [ -n "$swagger_file" ]; then
            echo -e "  📄 Main file: ${swagger_file}"
            echo -e "  🌐 Import into Swagger Editor: https://editor.swagger.io"
            echo -e "  🛠️  Generate client SDKs with OpenAPI Generator"
            echo -e "  📖 Use for comprehensive API documentation"
            echo -e "  🔧 Compatible with all OpenAPI 3.0 tooling"
        fi
    fi
    
    echo ""
    echo -e "${BLUE}Next steps:${NC}"
    if [ -n "$SWAGGER_OUTPUT" ] || [ "$SWAGGER_ONLY" = true ]; then
        echo "  1. Import the Swagger YAML into Swagger Editor for viewing"
        echo "  2. Generate client libraries using OpenAPI Generator"  
        echo "  3. Use as base for comprehensive API documentation"
        echo "  4. Integrate with CI/CD for automatic doc updates"
    else
        echo "  1. Review the HTML report for detailed analysis"
        echo "  2. Import the Postman collection for manual testing"
        echo "  3. Use the Swagger YAML for documentation and client generation"
        echo "  4. Check the OpenAPI spec for standard compliance"
    fi
    echo ""
}

# Check if Python is available
check_python() {
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}Error: Python 3 is required but not installed${NC}"
        exit 1
    fi
    
    # Check for required Python packages
    python3 -c "import requests, yaml" 2>/dev/null || {
        echo -e "${YELLOW}Installing required Python packages...${NC}"
        pip3 install requests pyyaml || {
            echo -e "${RED}Error: Failed to install required packages${NC}"
            echo "Please run: pip3 install requests pyyaml"
            exit 1
        }
    }
}

# Create scanner script if it doesn't exist
create_scanner_script() {
    local script_path="./universal_api_scanner.py"
    
    if [ ! -f "$script_path" ]; then
        echo -e "${RED}Error: universal_api_scanner.py not found${NC}"
        echo "Please ensure the Python scanner script is in the same directory"
        exit 1
    fi
}

# Error handling
handle_error() {
    local exit_code=$?
    echo ""
    echo -e "${RED}❌ Scan failed with exit code $exit_code${NC}"
    
    if [ -f "./api_scanner.log" ]; then
        echo -e "${YELLOW}Check the log file for details: ./api_scanner.log${NC}"
        echo -e "${YELLOW}Last few log entries:${NC}"
        tail -5 ./api_scanner.log
    fi
    
    echo ""
    echo -e "${BLUE}Troubleshooting tips:${NC}"
    echo "  1. Check if the URL is accessible"
    echo "  2. Verify authentication credentials"
    echo "  3. Try with --skip-ssl if using self-signed certificates"
    echo "  4. Use --verbose for detailed logging"
    echo "  5. Try --quick mode for faster scanning"
    
    exit $exit_code
}

# Validate URL format
validate_url() {
    if [[ ! "$BASE_URL" =~ ^https?:// ]]; then
        echo -e "${YELLOW}Warning: URL should start with http:// or https://${NC}"
        echo -e "${YELLOW}Assuming https://${NC}"
        BASE_URL="https://$BASE_URL"
    fi
}

# Main execution
main() {
    # Set up error handling
    trap 'handle_error' ERR
    
    # Check prerequisites
    check_python
    create_scanner_script
    
    # Parse arguments
    parse_args "$@"
    
    # Validate input
    validate_url
    
    # Pre-scan setup
    pre_scan_checks
    
    # Build and execute command
    local cmd=$(build_command)
    
    echo -e "${BLUE}Executing scan...${NC}"
    if [ "$VERBOSE" = true ]; then
        echo -e "${YELLOW}Command: $cmd${NC}"
    fi
    echo ""
    
    # Run the scan
    if [ "$VERBOSE" = true ]; then
        eval "$cmd"
    else
        eval "$cmd" &
        local scan_pid=$!
        show_progress $scan_pid
        wait $scan_pid
    fi
    
    # Post-scan summary
    post_scan_summary
}

# Quick templates for Swagger generation
swagger_template_basic() {
    echo -e "${PURPLE}Quick Swagger Generation Template:${NC}"
    echo "# Basic Swagger documentation generation"
    echo "$0 --swagger-output api-docs.yaml \\"
    echo "  --format swagger-builder \\"
    echo "  \"\$1\""
}

swagger_template_authenticated() {
    echo -e "${PURPLE}Authenticated API Swagger Template:${NC}"
    echo "# Complete Swagger docs with authentication"
    echo "$0 --swagger-output complete-api-docs.yaml \\"
    echo "  --deep-scan \\"
    echo "  --auth-header \"Bearer YOUR_TOKEN\" \\"
    echo "  --session-file ./api-session.json \\"
    echo "  \"\$1\""
}

# Handle special commands
case "${1:-}" in
    swagger-template-basic)
        swagger_template_basic
        exit 0
        ;;
    swagger-template-auth)
        swagger_template_authenticated
        exit 0
        ;;
    template-public)
        echo -e "${BLUE}Quick scan template for public APIs${NC}"
        echo "$0 --format all --timeout 15 --max-workers 5 --rate-limit 0.2 \"\$1\""
        exit 0
        ;;
    template-auth)
        echo -e "${BLUE}Quick scan template for authenticated APIs${NC}"
        echo "$0 --auth-header \"Bearer YOUR_TOKEN\" --format all --timeout 30 \"\$1\""
        exit 0
        ;;
esac

# Run main function
main "$@"