from setup import es

if es.indices.exists(index='analyzer-actions'):
    es.indices.delete(index='analyzer-actions')

if es.indices.exists(index='analyzer-actions-timestamps'):
    es.indices.delete(index='analyzer-action-timestamps')

if es.indices.exists(index='analyzer-errorlogs'):
    es.indices.delete(index='analyzer-errorlogs')

if es.indices.exists(index='analyzer-results'):
    es.indices.delete(index='analyzer-results')

if es.indices.exists(index='analyzer-sqlis'):
    es.indices.delete(index='analyzer-sqlis')

if es.indices.exists(index='analyzer-xsss'):
    es.indices.delete(index='analyzer-xsss')

if es.indices.exists(index='analyzer-fus'):
    es.indices.delete(index='analyzer-fus')

if es.indices.exists(index='analyzer-rules'):
    es.indices.delete(index='analyzer-rules')

if es.indices.exists(index='analyzer-yaras'):
    es.indices.delete(index='analyzer-yaras')

if es.indices.exists(index='analyzer-wordlists'):
    es.indices.delete(index='analyzer-wordlists')
