<script>
	import { config } from '$lib/stores';
	import { toast } from 'svelte-sonner';
	import { paymentsUser, getUsers } from '$lib/apis/setmenu';
	import Pagination from '$lib/components/common/Pagination.svelte';
	import Badge from '$lib/components/common/Badge.svelte';
	import Spinner from '$lib/components/common/Spinner.svelte';
	import dayjs from 'dayjs';
	import localizedFormat from 'dayjs/plugin/localizedFormat';
	dayjs.extend(localizedFormat);

	let page = 1;
	let users = null;
	let total = null;
	let menus = null;

	const getUserList = async () => {
		try {
			const res = await paymentsUser(localStorage.token, page, 30).catch((error) => {
				toast.error(`${error}`);
				return null;
			});

			if (res) {
				users = res.payments;
				total = res.total;
			}
		} catch (err) {
			console.error(err);
		}
	};

	const menuList = async () => {
		try {
			const res = await getUsers(localStorage.token, '', 'created_at', 'asc', page).catch(
				(error) => {
					toast.error(`${error}`);
					return null;
				}
			);

			if (res) {
				menus = res.plans ?? [];
			}
		} catch (err) {
			console.error(err);
		}
	};

	$: if (page) {
		getUserList();
		menuList();
	}
</script>

{#if ($config?.license_metadata?.seats ?? null) !== null && users.length > $config?.license_metadata?.seats}
	<div class=" mt-1 mb-2 text-xs text-red-500">
		<Banner
			className="mx-0"
			banner={{
				type: 'error',
				title: 'License Error',
				content:
					'Exceeded the number of seats in your license. Please contact support to increase the number of seats.',
				dismissable: true
			}}
		/>
	</div>
{/if}

{#if users === null || total === null}
	<div class="my-10">
		<Spinner />
	</div>
{:else}
	<div class="mt-0.5 mb-2 gap-1 flex flex-col md:flex-row justify-between">
		<div class="flex md:self-center text-lg font-medium px-0.5">
			<div class="flex-shrink-0">支付订单</div>
			<div class="flex self-center w-[1px] h-6 mx-2.5 bg-gray-50 dark:bg-gray-850" />

			{#if ($config?.license_metadata?.seats ?? null) !== null}
				{#if total > $config?.license_metadata?.seats}
					<span class="text-lg font-medium text-red-500"
						>{total} of {$config?.license_metadata?.seats}
						<span class="text-sm font-normal">available users</span></span
					>
				{:else}
					<span class="text-lg font-medium text-gray-500 dark:text-gray-300"
						>{total} of {$config?.license_metadata?.seats}
						<span class="text-sm font-normal">available users</span></span
					>
				{/if}
			{:else}
				<span class="text-lg font-medium text-gray-500 dark:text-gray-300">{total}</span>
			{/if}
		</div>
	</div>

	<div
		class="scrollbar-hidden relative whitespace-nowrap overflow-x-auto max-w-full rounded-sm pt-0.5"
	>
		<table
			class="w-full text-sm text-left text-gray-500 dark:text-gray-400 table-auto max-w-full rounded-sm"
		>
			<thead
				class="text-xs text-gray-700 uppercase bg-gray-50 dark:bg-gray-850 dark:text-gray-400 -translate-y-0.5"
			>
				<tr class="">
					<th scope="col" class="px-3 py-1.5 select-none">
						<div class="flex gap-1.5 items-center">支付id</div>
					</th>
					<th scope="col" class="px-3 py-1.5 select-none">
						<div class="flex gap-1.5 items-center">支付原因</div>
					</th>

					<th scope="col" class="px-3 py-1.5 select-none">
						<div class="flex gap-1.5 items-center">支付状态</div>
					</th>
					<th scope="col" class="px-3 py-1.5 select-none">
						<div class="flex gap-1.5 items-center">支付用户</div>
					</th>
					<th scope="col" class="px-3 py-1.5 select-none">
						<div class="flex gap-1.5 items-center">支付金额</div>
					</th>
					<th scope="col" class="px-3 py-1.5 select-none">
						<div class="flex gap-1.5 items-center">支付方式</div>
					</th>
					<th scope="col" class="px-3 py-1.5 select-none">
						<div class="flex gap-1.5 items-center">订单创建时间</div>
					</th>
				</tr>
			</thead>
			<tbody class="">
				{#each users as user, userIdx}
					<tr class="bg-white dark:bg-gray-900 dark:border-gray-850 text-xs">
						<td class=" px-3 py-1"> {user.id} </td>

						<td class=" px-3 py-1">
							{menus.find((menu) => menu.id === user.plan_id)?.name ?? '已失效套餐'}
						</td>

						<td class=" px-3 py-1">
							{#if user.status == 'completed'}
								<Badge type="success" content="已支付" />
							{:else}
								<Badge type="muted" content="未支付" />
							{/if}
						</td>
						<td class=" px-3 py-1"> {user.user_name} </td>
						<td class=" px-3 py-1"> {user.amount} </td>
						<td class=" px-3 py-1"> {user.payment_method} </td>
						<td class=" px-3 py-1">
							{dayjs(user.updated_at * 1000).format('LL')}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>

	<Pagination bind:page count={total} perPage={30} />
{/if}
