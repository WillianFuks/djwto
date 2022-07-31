<template>
  <q-layout view="lHh Lpr lFf">
    <q-header
      elevated
      class="bg-warning text-dark"
    >
      <q-toolbar
        class="row justify-between"
      >

        <q-toolbar-title
          shrink
          class="no-padding text-dark text-h4"
        >
          sandbox
        </q-toolbar-title>

        <q-toolbar-title
          shrink
          :style="{ 'margin-right': isLoginPage ? 'auto' : 'None' }"
        >
          djwto
        </q-toolbar-title>

        <div
          v-if="!isLoginPage"
          style="margin-left:auto"
        >
          <q-tabs>
            <q-btn-dropdown
              color="black"
              push
              flat
              fab
            >
              <template #label>
                <div class="no-wrap">
                  <q-icon left name="fas fa-user" />
                </div>
              </template>

              <q-list>
                <q-item v-close-popup clickable @click="onLogOut">
                  <q-item-section>
                    <q-item-label style="font-size:16px">Logout</q-item-label>
                  </q-item-section>
                  <q-item-section avatar>
                    <q-avatar icon="fa-solid fa-arrow-right-from-bracket" color="black" text-color="white" />
                  </q-item-section>

                </q-item>

              </q-list>
            </q-btn-dropdown>
          </q-tabs>
        </div>

      </q-toolbar>
    </q-header>

    <q-page-container>
      <router-view />
    </q-page-container>
  </q-layout>
</template>

<script setup>
  import { ref, computed } from 'vue'
  import { api } from 'boot/axios'
  import { useRouter, useRoute } from 'vue-router';
  import { getCookie } from '../../utils'

  const router = useRouter();
  const route = useRoute();
  const leftDrawerOpen = ref(false)

  const isLoginPage = computed(() => {
    return route.name === 'login'
  })

  function toggleLeftDrawer() {
    leftDrawerOpen.value = !leftDrawerOpen.value
  }

  const onLogOut = () => {
    const postData = new FormData();
    postData.append("jwt_type", "refresh");
    const csrftoken = getCookie("csrftoken");

    let res = api.post(
      'https://api.example.com:8002/api/token/refresh/logout/',
      postData,
      {
        withCredentials: true,
        headers: {
          'X-CSRFToken': csrftoken,
          'Content-Type': 'application/json'
        }
      }
    )
    .then((response) => {
      console.log(response)
    })
    .catch((r) => {
      console.log('r: ', r.response)
    })

    let del_res = api.delete(
      'https://api.example.com:8002/api/token/refresh/logout/',
      {
        withCredentials: true,
        headers: {
          'X-CSRFToken': csrftoken,
          'Content-Type': 'application/json'
        },
        data: postData
      },
    )
    .then((response) => {
      router.push({name: 'login' })
    })
    .catch((r) => {
      router.push({name: 'login' })
    })
  }
</script>
