import { route } from "quasar/wrappers";
import {
  createRouter,
  createMemoryHistory,
  createWebHistory,
  createWebHashHistory,
} from "vue-router";
import routes from "./routes";
import { getCookie, refreshToken } from "../../utils";

/*
 * If not building with SSR mode, you can
 * directly export the Router instantiation;
 *
 * The function below can be async too; either use
 * async/await or return a Promise which resolves
 * with the Router instance.
 */

export default route(function (/* { store, ssrContext } */) {
  const createHistory = process.env.SERVER
    ? createMemoryHistory
    : process.env.VUE_ROUTER_MODE === "history"
    ? createWebHistory
    : createWebHashHistory;

  const Router = createRouter({
    scrollBehavior: () => ({ left: 0, top: 0 }),
    routes,

    // Leave this as is and make changes in quasar.conf.js instead!
    // quasar.conf.js -> build -> vueRouterMode
    // quasar.conf.js -> build -> publicPath
    history: createHistory(process.env.VUE_ROUTER_BASE),
  });

  /*  Router.beforeEach((to, from, next) => {*/
  /*console.log(`this is to: ${to}`);*/
  /*console.log(`this is from: ${from}`);*/
  /*if (to.name !== "login") {*/
  /*const jwt_access = getCookie("jwt_access_payload");*/
  /*console.log(`this is jwt_access: ${jwt_access}`);*/
  /*if (jwt_access === void 0) {*/
  /*const res = refreshToken();*/
  /*res.then(() => {*/
  /*const jwt_access2 = getCookie("jwt_access_payload");*/
  /*if (jwt_access2 === void 0) {*/
  /*next({ name: "login" });*/
  /*} else {*/
  /*next();*/
  /*}*/
  /*});*/
  /*} else {*/
  /*next();*/
  /*}*/
  /*} else {*/
  /*next();*/
  /*}*/
  /*});*/

  return Router;
});
