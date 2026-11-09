<#
.SYNOPSIS
    Automated provisioner for Azure DevOps Organizations, Projects, and Repositories fleet.

.DESCRIPTION
    Creates enterprise-grade projects and repositories in Azure DevOps.
    Because Azure DevOps Services restricts root organization creation (dev.azure.com/{org})
    to interactive authentication via https://aex.dev.azure.com or Azure Portal, this script:
    1. Operates against specified target organization(s).
    2. Provisions 5 structured projects per organization.
    3. Provisions 5 repositories per project with standard branch topologies (main, develop, release/*).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$Orgs = @("ado-policy-testing"),

    [Parameter(Mandatory = $false)]
    [string]$Pat = "",

    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $Pat) {
    $Pat = [Environment]::GetEnvironmentVariable("ADO_PAT", "User")
    if (-not $Pat) { $Pat = $env:ADO_PAT }
}

if (-not $Pat) {
    throw "Azure DevOps Personal Access Token (PAT) not found. Set `$env:ADO_PAT or pass -Pat."
}

$b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$Pat"))
$headers = @{
    Authorization  = "Basic $b64"
    "Content-Type" = "application/json"
}

# Process template ID for Agile / Basic
$templateTypeId = "b8a3a935-7e91-48b8-a94c-606d37c3e9f2" # Basic template

# Define Enterprise Domain Blueprint (6 Domains x 5 Projects x 5 Repos)
$EnterpriseBlueprint = [ordered]@{
    "Fintech-Payments" = @{
        Description = "Core Banking, Transaction Processing, and Digital Wallet Platform"
        Projects    = [ordered]@{
            "PaymentGateway-Core" = @("api-service", "settlement-engine", "web-portal", "infra-terraform", "client-sdk")
            "Ledger-Accounting"   = @("journal-service", "balance-reconciliation", "audit-exporter", "database-migration", "shared-models")
            "Fraud-Detection"     = @("rules-engine", "anomaly-ml-service", "event-streaming", "analyst-dashboard", "alert-dispatcher")
            "Customer-Wallet"     = @("wallet-api", "rewards-service", "mobile-bff", "web-checkout", "card-tokenization")
            "CrossBorder-Remit"   = @("fx-pricing", "swift-connector", "compliance-sanctions", "remittance-api", "partner-webhook")
        }
    }
    "Retail-Commerce" = @{
        Description = "Omnichannel E-Commerce, Order Management, and Search Platform"
        Projects    = [ordered]@{
            "Catalog-Search"      = @("search-engine", "product-indexing", "taxonomy-service", "category-manager", "media-cdn")
            "Order-Fulfillment"   = @("order-lifecycle-api", "cart-checkout", "returns-rma", "notification-hub", "event-stream")
            "Inventory-Warehouse" = @("stock-allocation", "warehouse-scanner", "asn-inbound", "safety-stock-ml", "supplier-edi")
            "Pricing-Promotions"  = @("discount-calculator", "coupon-engine", "dynamic-pricing", "campaign-manager", "loyalty-tiers")
            "Customer-Experience" = @("web-storefront", "mobile-ios", "mobile-android", "review-ratings", "personalization-api")
        }
    }
    "Healthcare-Clinical" = @{
        Description = "HIPAA-Compliant Electronic Health Records and Telehealth Platform"
        Projects    = [ordered]@{
            "Patient-Portal"      = @("portal-web", "appointment-booking", "prescription-refill", "auth-oauth-idp", "mobile-client")
            "EHR-Integrations"    = @("hl7-fhir-bridge", "epic-connector", "cerner-adapter", "lab-results-pipeline", "mpi-resolver")
            "Telehealth-Video"    = @("webrtc-signaling", "session-manager", "waiting-room", "recording-archiver", "chat-service")
            "Claims-Billing"      = @("claim-adjudication", "edi-837-generator", "remittance-835-parser", "icd10-coder", "billing-dashboard")
            "Clinical-Analytics"  = @("de-identification", "cohort-extractor", "quality-measures", "clinical-data-lake", "r-analytics-worker")
        }
    }
    "SupplyChain-Logistics" = @{
        Description = "Global Freight Tracking, Fleet Telematics, and Yard Management"
        Projects    = [ordered]@{
            "Fleet-Telematics"    = @("iot-ingestion", "gps-geofence", "vehicle-diagnostics", "driver-mobile-app", "telemetry-stream")
            "Route-Optimizer"     = @("dispatch-planner", "traffic-routing-api", "fuel-efficiency-ml", "stops-sequencer", "routing-ui")
            "Yard-Management"     = @("gate-checkin", "dock-scheduler", "trailer-tracking", "rfid-reader-agent", "yard-map-web")
            "Customs-Compliance"  = @("trade-documentation", "tariff-harmonizer", "manifest-filing", "export-license-audit", "audit-vault")
            "Carrier-Procurement" = @("spot-auction-api", "contract-lifecycle", "rate-matrix-engine", "carrier-portal", "invoice-settlement")
        }
    }
    "CyberSec-Identity" = @{
        Description = "Zero-Trust Architecture, Privileged Identity, and Threat Monitoring"
        Projects    = [ordered]@{
            "ZeroTrust-Proxy"     = @("reverse-proxy", "policy-decision-point", "mtls-terminator", "session-evaluator", "client-sidecar")
            "IAM-Directory"       = @("scim-sync-engine", "rbac-assignment-api", "mfa-fido2-service", "lifecycle-joiner-mover", "admin-console")
            "Threat-Intelligence" = @("siem-connector", "ioc-feed-ingest", "threat-graph-db", "correlation-rules", "mitre-mapper")
            "Audit-Compliance"    = @("immutable-audit-log", "soc2-evidence-collector", "policy-as-code", "drift-detector", "reporting-portal")
            "Secrets-Vault"       = @("key-management-api", "certificate-rotator", "secret-broker", "hsm-hardware-driver", "cli-vault-tool")
        }
    }
    "Data-AI-Platform" = @{
        Description = "Enterprise Data Lakehouse, Feature Store, and ML Model Governance"
        Projects    = [ordered]@{
            "Feature-Store"       = @("online-kv-store", "offline-parquet-sync", "feature-definitions", "lineage-tracker", "client-sdk-py")
            "Model-Serving"       = @("triton-k8s-runtime", "inference-gateway", "canary-traffic-router", "monitoring-drift", "onnx-converter")
            "Data-Lakehouse"      = @("iceberg-metastore", "dbt-transformations", "spark-ingest-jobs", "data-quality-great-expectations", "storage-catalog")
            "Streaming-Pipelines" = @("kafka-stream-topology", "flink-realtime-joins", "schema-registry", "cdc-debezium-sync", "dead-letter-retry")
            "Enterprise-BI"       = @("semantic-layer-cube", "powerbi-dataset-sync", "superset-dashboards", "data-dictionary-portal", "metrics-catalog-api")
        }
    }
}

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "      Azure DevOps Enterprise Fleet Provisioner                  " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Target Organizations : $($Orgs -join ', ')"
Write-Host "Blueprint Domains    : $($EnterpriseBlueprint.Keys.Count) domains"
Write-Host "Projects per Domain  : 5 projects"
Write-Host "Repos per Project    : 5 repositories"
Write-Host "Total Fleet Size     : $($Orgs.Count) Org(s) x 30 Projects x 150 Repositories"
Write-Host "-----------------------------------------------------------------"

if ($DryRun) {
    Write-Host "`n[DRY RUN PREVIEW] The following structure will be provisioned:" -ForegroundColor Yellow
    foreach ($org in $Orgs) {
        Write-Host "`n=== Organization: $org ===" -ForegroundColor Cyan
        foreach ($domainName in $EnterpriseBlueprint.Keys) {
            $domain = $EnterpriseBlueprint[$domainName]
            Write-Host "`n  Domain: $domainName ($($domain.Description))" -ForegroundColor Green
            foreach ($projName in $domain.Projects.Keys) {
                $fullProjName = "$domainName-$projName"
                $repos = $domain.Projects[$projName]
                Write-Host "    * Project: $fullProjName" -ForegroundColor White
                foreach ($repo in $repos) {
                    Write-Host "        - Repo: $repo (Branches: main, develop, release/v1.0)" -ForegroundColor Gray
                }
            }
        }
    }
    Write-Host "`n[DRY RUN] Complete. No changes were made." -ForegroundColor Yellow
    return
}

# Live Provisioning
foreach ($org in $Orgs) {
    Write-Host "`n>>> Processing Organization: $org <<<" -ForegroundColor Cyan
    $orgBaseUrl = "https://dev.azure.com/$org"

    # Query existing projects to avoid duplicate creation errors
    $existingProjects = @{}
    try {
        $pRes = Invoke-RestMethod -Uri "$orgBaseUrl/_apis/projects?api-version=7.0" -Headers $headers
        if ($pRes.value) {
            foreach ($p in $pRes.value) {
                $existingProjects[$p.name.ToLower()] = $p
            }
        }
    } catch {
        Write-Warning "Failed to query existing projects in $org : $($_.Exception.Message)"
    }

    foreach ($domainName in $EnterpriseBlueprint.Keys) {
        $domain = $EnterpriseBlueprint[$domainName]
        Write-Host "`n  [+] Provisioning Domain: $domainName" -ForegroundColor Cyan

        foreach ($projKey in $domain.Projects.Keys) {
            $projName = "$domainName-$projKey"
            $projDesc = "$($domain.Description) - Subsystem $projKey"
            $repos = $domain.Projects[$projKey]

            # 1. Project Creation
            $projObj = $null
            if ($existingProjects.ContainsKey($projName.ToLower())) {
                $projObj = $existingProjects[$projName.ToLower()]
                Write-Host "    [EXISTS] Project '$projName' already exists (ID: $($projObj.id))." -ForegroundColor Gray
            } else {
                Write-Host "    [CREATE] Creating Project '$projName'..." -ForegroundColor White
                $bodyProj = @{
                    name         = $projName
                    description  = $projDesc
                    visibility   = "private"
                    capabilities = @{
                        versioncontrol  = @{ sourceControlType = "Git" }
                        processTemplate = @{ templateTypeId = $templateTypeId }
                    }
                } | ConvertTo-Json -Depth 5

                try {
                    $opRes = Invoke-RestMethod -Uri "$orgBaseUrl/_apis/projects?api-version=7.0" -Method Post -Headers $headers -Body $bodyProj
                    $opId = $opRes.id
                    # Poll for completion (up to 30s)
                    $pAttempt = 0
                    while ($pAttempt -lt 15) {
                        Start-Sleep -Seconds 2
                        $pAttempt++
                        $opStatus = Invoke-RestMethod -Uri "$orgBaseUrl/_apis/operations/$opId`?api-version=7.0" -Headers $headers
                        if ($opStatus.status -eq 'succeeded') { break }
                    }
                    $projObj = Invoke-RestMethod -Uri "$orgBaseUrl/_apis/projects/$projName`?api-version=7.0" -Headers $headers
                    Write-Host "    [OK] Project '$projName' created successfully (ID: $($projObj.id))." -ForegroundColor Green
                } catch {
                    Write-Warning "    [ERROR] Failed to create project '$projName': $($_.Exception.Message)"
                    continue
                }
            }

            # 2. Query Existing Repositories in this Project
            $existingRepos = @{}
            try {
                $rRes = Invoke-RestMethod -Uri "$orgBaseUrl/$($projObj.id)/_apis/git/repositories?api-version=7.0" -Headers $headers
                if ($rRes.value) {
                    foreach ($r in $rRes.value) { $existingRepos[$r.name.ToLower()] = $r }
                }
            } catch {
                Write-Warning "    Failed to list repositories: $($_.Exception.Message)"
            }

            # 3. Create & Initialize 5 Repositories
            foreach ($repoName in $repos) {
                $repoObj = $null
                if ($existingRepos.ContainsKey($repoName.ToLower())) {
                    $repoObj = $existingRepos[$repoName.ToLower()]
                    Write-Host "      - [EXISTS] Repo '$repoName' already exists." -ForegroundColor Gray
                } else {
                    Write-Host "      - [CREATE] Creating Repo '$repoName'..." -ForegroundColor White
                    try {
                        $bodyRepo = @{ name = $repoName } | ConvertTo-Json
                        $repoObj = Invoke-RestMethod -Uri "$orgBaseUrl/$($projObj.id)/_apis/git/repositories?api-version=7.0" -Method Post -Headers $headers -Body $bodyRepo
                        Write-Host "        [OK] Repo '$repoName' created (ID: $($repoObj.id))." -ForegroundColor Green
                    } catch {
                        Write-Warning "        [FAIL] Failed to create repo '$repoName': $($_.Exception.Message)"
                        continue
                    }
                }

                # 4. Initialize repository with initial commit and branches if empty
                try {
                    $refs = (Invoke-RestMethod -Uri "$orgBaseUrl/$($projObj.id)/_apis/git/repositories/$($repoObj.id)/refs?api-version=7.0" -Headers $headers).value
                    if (-not $refs -or $refs.Count -eq 0) {
                        # Push initial commit to main
                        $bodyMain = @{
                            refUpdates = @(@{ name = "refs/heads/main"; oldObjectId = "0000000000000000000000000000000000000000" })
                            commits    = @(@{
                                comment = "Initial commit for $repoName in $projName"
                                changes = @(@{
                                    changeType = "add"
                                    item       = @{ path = "/README.md" }
                                    newContent = @{
                                        content     = "# $repoName`n`nEnterprise service under project **$projName** ($domainName).`n`nManaged in Azure DevOps."
                                        contentType = "rawtext"
                                    }
                                })
                            })
                        } | ConvertTo-Json -Depth 6

                        $pushRes = Invoke-RestMethod -Uri "$orgBaseUrl/$($projObj.id)/_apis/git/repositories/$($repoObj.id)/pushes?api-version=7.0" -Method Post -Headers $headers -Body $bodyMain
                        $commitId = $pushRes.commits[0].commitId

                        # Create develop branch and release/v1.0 branch
                        $branchBody = @(
                            @{ name = "refs/heads/develop"; oldObjectId = "0000000000000000000000000000000000000000"; newObjectId = $commitId },
                            @{ name = "refs/heads/release/v1.0"; oldObjectId = "0000000000000000000000000000000000000000"; newObjectId = $commitId }
                        ) | ConvertTo-Json -Depth 5
                        $null = Invoke-RestMethod -Uri "$orgBaseUrl/$($projObj.id)/_apis/git/repositories/$($repoObj.id)/refs?api-version=7.0" -Method Post -Headers $headers -Body $branchBody
                        Write-Host "        [INITIALIZED] Pushed initial commit and created branches (main, develop, release/v1.0)" -ForegroundColor Green
                    }
                } catch {
                    # Non-fatal if already initialized
                }
            }
        }
    }
}

Write-Host "`n=================================================================" -ForegroundColor Green
Write-Host "      Azure DevOps Enterprise Fleet Provisioning Complete!       " -ForegroundColor Green
Write-Host "=================================================================`n" -ForegroundColor Green
