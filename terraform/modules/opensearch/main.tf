locals {
  collection_name = "${var.project}-vector"
  vector_index    = "${var.project}-runbooks-index"
  embedding_model = coalesce(var.embedding_model_arn, "arn:aws:bedrock:${var.region}::foundation-model/amazon.titan-embed-text-v2:0")
}

resource "aws_opensearchserverless_security_policy" "encryption" {
  name = "${var.project}-encryption"
  type = "encryption"

  policy = jsonencode({
    Rules = [
      {
        Resource     = ["collection/${local.collection_name}"]
        ResourceType = "collection"
      }
    ]
    AWSOwnedKey = true
  })
}

resource "aws_opensearchserverless_security_policy" "network" {
  name = "${var.project}-network"
  type = "network"

  policy = jsonencode([
    {
      Rules = [
        {
          Resource     = ["collection/${local.collection_name}"]
          ResourceType = "collection"
        }
      ]
      AllowFromPublic = true
    }
  ])
}

resource "aws_opensearchserverless_collection" "this" {
  name = local.collection_name
  type = "VECTORSEARCH"

  depends_on = [
    aws_opensearchserverless_security_policy.encryption,
    aws_opensearchserverless_security_policy.network
  ]
}

resource "aws_opensearchserverless_access_policy" "this" {
  name = "${var.project}-access"
  type = "data"

  policy = jsonencode([
    {
      Description = "Access policy for vector search collection"
      Rules = [
        {
          ResourceType = "collection"
          Resource     = ["collection/${local.collection_name}"]
          Permission = [
            "aoss:*"
          ]
        },
        {
          ResourceType = "index"
          Resource     = ["index/${local.collection_name}/*"]
          Permission = [
            "aoss:*"
          ]
        }
      ]
      Principal = [var.bedrock_kb_role_arn, var.lambda_role_arn, var.admin_principal_arn]
    }
  ])
}
