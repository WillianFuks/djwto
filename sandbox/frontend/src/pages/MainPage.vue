<template>
  <q-page padding>
    <p>{{ data }}</p>
  </q-page>
</template>

<script setup>
  import { ref } from 'vue'
  import { api } from 'boot/axios'
  import { useQuasar } from 'quasar'
  import { useRouter } from 'vue-router';
  import { getCookie } from '../../utils'

  const data = ref(null)

  const $q = useQuasar()

  function loadData() {
    const csrftoken = getCookie("csrftoken");
    console.log(`This is the obtained CSRF: ${csrftoken}`)
    const postData = new FormData()

    let res = api.post(
      'https://api.example.com:8002/data/',
      postData,
      {
        withCredentials: true,
        headers: {
          'Content-Type': 'application/json',
          "X-CSRFToken": csrftoken,
        }
      }
    ).then((response) => {
      data.value = JSON.parse(JSON.stringify(response.data.data))
    }).catch((r) => {
      const error = JSON.parse(r.response.data.error)
      for (let [key, value] of Object.entries(error)){
        if (key == '__all__') {
          key = ''
        }
        $q.notify({
          color: 'red-5',
          textColor: 'white',
          icon: 'warning',
          message: `${key} ${value}`
        })
      }
    })
  }
  loadData()
</script>
