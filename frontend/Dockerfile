# ============================================================
#  프론트엔드 정적 서빙 + API 프록시 (nginx)
# ============================================================
FROM nginx:1.27-alpine

# 기본 설정 대체
RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/app.conf

# 정적 자산
COPY index.html /usr/share/nginx/html/index.html
COPY css/ /usr/share/nginx/html/css/
COPY js/  /usr/share/nginx/html/js/

EXPOSE 80
