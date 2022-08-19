export function getCookie(cName) {
  const name = cName + "=";
  const cDecoded = decodeURIComponent(document.cookie);
  const cArr = cDecoded.split("; ");
  let res;
  cArr.forEach((val) => {
    if (val.indexOf(name) === 0) res = val.substring(name.length);
  });
  return res;
}

import { api } from "boot/axios";
export async function refreshToken($q, router) {
  const csrftoken = getCookie("csrftoken");
  const postData = new FormData();

  postData.append("jwt_type", "refresh");

  let res = api
    .post(
      `https://${process.env.BACK_DOMAIN || "api.example.com"}${
        process.env.BACK_DOMAIN !== undefined ? "" : ":8002"
      }/api/token/refresh/refresh_access/`,
      postData,
      {
        withCredentials: true,
        headers: {
          "X-CSRFToken": csrftoken,
          "Content-Type": "application/json",
        },
      }
    )
    .then((response) => {
      if ($q !== void 0) {
        $q.notify({
          message: "Login refreshed. Try again please.",
          icon: "far fa-check-circle",
          color: "info",
          classes: "text-subtitle1",
          position: "top",
        });
      }
    })
    .catch((r) => {
      if ($q !== void 0) {
        $q.notify({
          message: "Login Required!",
          icon: "fas fa-exclamation-triangle",
          color: "negative",
          classes: "text-subtitle1",
          position: "top",
        });
      }
      if (router !== void 0) {
        router.push({ name: "Login" });
      }
    });
  return res;
}
