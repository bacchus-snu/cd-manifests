현재 foundation/argo 및 talos 폴더만 사용중

## argoCD
- top-level이라는 app이 다른 모든 앱을 만드는 구조
- top-level app이 각 하위 폴더의 app.yaml파일을 참조

### argoCD가 참조하는 repository,branch 바꾸기
1. targetRevision: (브랜치이름)이라고 적힌 파일을 모두 수정
2. 수정 후 kubectl apply -f top-level.yaml 적용
3. argocd.bacchus.io에서 sync

## talos
TODO