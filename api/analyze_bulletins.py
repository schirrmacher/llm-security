#!/usr/bin/env python3
# This script helps engineers to analyze security bulletins so that we know if we are affected by security issues.


from llama_index.core import VectorStoreIndex
from llama_index.llms.mistralai import MistralAI
from dotenv import load_dotenv
from llama_index.core import download_loader
from llama_index.core import Settings
from llama_index.embeddings.fastembed import FastEmbedEmbedding


def main():

    llm = MistralAI(model="mistral-large-latest")

    embed_model = FastEmbedEmbedding(model_name="BAAI/bge-small-en-v1.5")
    Settings.embed_model = embed_model
    Settings.chunk_size = 1024
    Settings.llm = llm

    load_dotenv()

    urls = [
        "https://cloud.google.com/anthos/clusters/docs/security-bulletins",
        "https://cloud.google.com/support/bulletins",
        "https://openjdk.org/groups/vulnerability/advisories/",
        "https://spring.io/security",
        "https://www.cvedetails.com/vulnerability-list/vendor_id-14185/Golang.html",
        "https://auth0.com/docs/secure/security-guidance/security-bulletins",
    ]
    prompt = "We are Google Cloud customers and apply Google Kubernetes Engine with version 1.27.13. Are there update recommendations for us?"

    BeautifulSoupWebReader = download_loader("BeautifulSoupWebReader")
    loader = BeautifulSoupWebReader()
    documents = loader.load_data(urls=urls)

    index = VectorStoreIndex.from_documents(documents)
    query_engine = index.as_query_engine()

    response = query_engine.query(prompt)
    print(f"RESPONSE:\n{response}")


if __name__ == "__main__":
    main()
